rule irctelnet__loader: malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects dropper of the irctelnet - 20161102"
                                        
    strings:
        $x_00 = "mkdir -p "
        $x_01 = "&& rm -f "
        $x_02 = "ftpget -u ftp "
        $x_03 = "2>&1 ||"
        $x_04 = "wget -O"
        $x_05 = "tftp -g -r"
        $x_06 = "2>&1 &&"
        $x_07 = "chmod +x "
        $x_08 = "&& sh "

    condition:
                all of ($x_*)
}