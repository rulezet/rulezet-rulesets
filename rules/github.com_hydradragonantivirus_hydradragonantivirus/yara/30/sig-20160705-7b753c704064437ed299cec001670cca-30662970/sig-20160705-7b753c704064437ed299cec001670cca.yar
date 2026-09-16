rule sig_20160705_7b753c704064437ed299cec001670cca {
  meta:
    description = "datamaliciousorder - file 20160705_7b753c704064437ed299cec001670cca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff2b459691873d715c6ab8afb1d63282e8f993ba1a61db3c265550d528b67e80"

  strings:
    $x1 = "function z52(l75,y40) {d78[l75] = y40;}; var d78 = new Array();z52(228, 'ws.');z52(145, 'xist');z52(202, 'typ');z52(869, ' ws.Ru" ascii
    $s2 = "(793, 'pen\"');z52(771, '+\"C');z52(635, 'n help');z52(712, ' \"+cq+');z52(430, '.Wri');z52(783, '\"HK');z52(789, 'cs+');z52(865" ascii
    $s3 = "897, 'Cr');z52(53, 'hat');z52(9, '815');z52(688, '    - ');z52(99, 'cs+');z52(580, 'ine(\"');z52(680, ' make ');z52(550, 'in');z" ascii
    $s4 = "txt');z52(323, 'e(\"A');z52(384, 'r file');z52(590, 'files');z52(233, 'xe\"');z52(574, 'ite');z52(364, 'ng ');z52(477, 'ttps:');" ascii
    $s5 = "function z52(l75,y40) {d78[l75] = y40;}; var d78 = new Array();z52(228, 'ws.');z52(145, 'xist');z52(202, 'typ');z52(869, ' ws.Ru" ascii
    $s6 = " 'po');z52(460, 'C with');z52(721, '+\"Win');z52(362, 'ypt');z52(313, 'ext');z52(131, 'eObje');z52(16, '=Strin');z52(361, 'ncr')" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and all of them
}