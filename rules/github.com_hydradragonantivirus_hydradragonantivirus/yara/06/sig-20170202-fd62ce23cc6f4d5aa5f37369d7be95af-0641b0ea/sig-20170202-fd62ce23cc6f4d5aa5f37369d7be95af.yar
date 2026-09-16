rule sig_20170202_fd62ce23cc6f4d5aa5f37369d7be95af {
  meta:
    description = "datamaliciousorder - file 20170202_fd62ce23cc6f4d5aa5f37369d7be95af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91edfdb1b5e4670227624c59ce877d3daed0507533419d5cecde1e692e91c2bb"

  strings:
    $s1 = "if ([\"eva800func\", \"qfu118ytk\", \"yqe346ahe\", \"ta439rsaxz\", \"xy373oz\", \"dubu165odg\", new Function([\"utohx248ce\", \"" ascii
    $s2 = "enyqruledcostiporpejqivisgozafrygizypigadinwuwnewdojhoncozylamiwisfyscagsebwezvyrbehvarmorikmasvevakakalkofsigwejfehhonurgelruce" ascii
    $s3 = "if ([\"eva800func\", \"qfu118ytk\", \"yqe346ahe\", \"ta439rsaxz\", \"xy373oz\", \"dubu165odg\", new Function([\"utohx248ce\", \"" ascii
    $s4 = "fwuwixcekizriwepu0 = this[[\"utrykc791uk\", \"ufew759yt\", [\"syflo371ydcyz\", \"amr167mtof\", \"WSc\"][2], \"ezb566bmaho\", \"o" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}