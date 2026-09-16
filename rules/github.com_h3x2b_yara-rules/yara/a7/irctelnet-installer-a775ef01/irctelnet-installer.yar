rule irctelnet__installer: malware linux
{
    meta:
        author = "@h3x2b <tracker@h3x.eu>"
        description = "Detects malicious payload of the irctelnet - 20161102"
                                        
    strings:
        $x_00 = "x32bin="
        $x_01 = "armbin="
        $x_02 = "mpsbin="
                $x_04 = "ppcbin="
        $x_05 = "sphbin="
        $x_06 = "sprbin="
        $x_07 = "ulimit -n 4096"
        $x_08 = "ip="
        $x_09 = "dir="
        $x_10 = "me="
        $x_11 = "killall -9 $"
        $x_12 = "rm -f $"
        $x_13 = "wget -O $"
        $x_14 = " && chmod +x $"
        $x_15 = " && $"
                

    condition:
                all of ($x_*)
}