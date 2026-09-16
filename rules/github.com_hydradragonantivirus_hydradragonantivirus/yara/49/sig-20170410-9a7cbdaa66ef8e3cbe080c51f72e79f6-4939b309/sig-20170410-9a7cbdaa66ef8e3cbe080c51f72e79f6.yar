rule sig_20170410_9a7cbdaa66ef8e3cbe080c51f72e79f6 {
  meta:
    description = "datamaliciousorder - file 20170410_9a7cbdaa66ef8e3cbe080c51f72e79f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b7216b1177ed76c12009ec2224a816d0a2e74a17cf69c19b87163df8b8196f8"

  strings:
    $x1  = "                            gz[[\"run\"][0]]([sets(0, \"fn\", [\"cmd.exe /c \\\"powershe\"]) + Some(0, \"a8c\", [\"ll  $urna='^ " ascii
    $x2  = "                            gz[[\"run\"][0]]([sets(0, \"fn\", [\"cmd.exe /c \\\"powershe\"]) + Some(0, \"a8c\", [\"ll  $urna='^ " ascii
    $s3  = "nix(0, \"rem\", [\"'^ss; $path=($e';$ti\"]) + plan(0, \"sup\", [\"nt='^Set-Execution';\"]) + gasp(0, \"aka\", [\"$Run='^nv:temp+" ascii
    $s4  = "+ A(0, \"IP\", [\" Bypass';$IRC='^user\"]) + f126(0, \"init\", [\".php?f=2.';$e077='^e\"]) + STOR(0, \"aa\", [\"lopoenz.top/';$f" ascii
    $s5  = "+ city(0, \"TRUE\", [\"$e189='^e(''http://n\"]) + Isle(0, \"r\", [\"ob';$br='^.exe'');(N\"]) + hack(0, \"INI\", [\"ew-O';$_dfw='" ascii
    $s6  = "var e188 = undefined; /* Jew is the 'poisonous mushroom' of the civilized world.  */" fullword ascii
    $s7  = "(0, \"zu\", [\"br+$ki+$e159+$No+$e1\"]) + far(0, \"echo\", [\"89+$e077+$IRC+$ie+$S\"]) + Copy(0, \"xls\", [\"ite+$urna);\\\\\\\"" ascii
    $s8  = "// flooded the economic enterprises and administrative ap- " fullword ascii
    $s9  = " lot(0, \"ISO\", [\"S';$Site='^Start-Pro\"]) + meet(0, \"x1\", [\"cess';$I='^ -Scope P\"]) + Hac(0, \"num\", [\"roce';$ki='^bjec" ascii
    $s10 = "var e097 = false; /* Czech nation above those of the Church, thus becoming  */" fullword ascii
    $s11 = "0, \"_0\", [\"t.Webclient'; Invoke\"]) + rsd(0, \"sake\", [\"-Expression ($tint+$\"]) + fade(0, \"ajax\", [\"_dfw+$I+$f141+$Run+" ascii
    $s12 = "7(0, \"May\", [\"stem.';$No='^).Downl\"]) + uri(0, \"nx\", [\"oadFil';$ie='^gif'',\"]) + e063(0, \"e197\", [\"$path); ';$e159='^" ascii
    $s13 = "var cos = '43400'; /* measures as means of defense.  */" fullword ascii
    $s14 = "} /* the previous doings of parties appear as no longer suitable  */" fullword ascii
    $s15 = "} /* could believe only with difficulty that these were supposed  */" fullword ascii
    $s16 = "var sync = null; /*  */" fullword ascii
    $s17 = "// To me personally those hours appeared like the redemp- " fullword ascii
    $s18 = "} /* people remains indifferent. They are only Germans!  */" fullword ascii
    $s19 = "} /* 454 MEIN KAMPF  */" fullword ascii
    $s20 = "// community? For here, too, everything is purloined, or " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}