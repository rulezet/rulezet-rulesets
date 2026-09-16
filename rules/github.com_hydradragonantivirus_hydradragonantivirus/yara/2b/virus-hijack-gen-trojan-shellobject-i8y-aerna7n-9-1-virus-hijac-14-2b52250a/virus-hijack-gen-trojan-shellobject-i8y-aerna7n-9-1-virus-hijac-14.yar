import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_9_1_Virus_Hijac_14 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@amWqEpo_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15fdf6d377a0a52486c0c977220c9e29550f849e6046ed98cb1336e94c9b8c86"
    hash2       = "398c94f364a2012ae83dd0019566925d1b1742e847dbf6c91d2534b7ed43ee2b"

  strings:
    $s1  = "KLOGHKCDJBCKCDNFGB;>A:=A:=@9<@9<C<?C<?D=@D=@E>AF?BG@CG@CB;>B;>B;>B;>B;>B;>B;>B;>D=@C<?A:=?8;=69;47:36925:36<58=69@9<C<?E>AG@CHAD" ascii
    $s2  = "D<@A<?C9BG<@GGCIFAIB@HBGKDFICBLDGOGGGGGC9GE>FB;8C<>G:GB8@@8@@8CA>A@:BD9GG=FA:GC8?:8=<6<>58F:9D9AGG@@AD@<EF???????=C8<@<FAFEF>A@9" ascii
    $s3  = "\\SS>10XPXH@@h``VIRE<ARORSJWE9BNBEKDEMBFPJJA<A?68" fullword ascii
    $s4  = "(No Name)Circular references not allowed" fullword wide
    $s5  = "@HH@HP@JTJHTHLPHHPHHPHHPHHPHHPHPPHH000000000000800?11820:0880;808808808A;8@<@D8@@<AD=C@@B@@@DAFVIHHAHH@GHCG@@D@@@HDDMC@HB@H@BIFF" ascii
    $s6  = "AJ@@LEGJCDNGCNADOGGOGOSMOVMWPNSRIKUNJLBNOE@A>FC9FA<GL9AICESIKRIPH8@H@@HECH@DH@HPHHPJKTKHRNLRHHPHHPHJRLKPIJQLISOHWALPAHPFNSMOTIHP" ascii
    $s7  = "977NLLUSSZUVKFGTOPRMNRLMWQRMGHOIJRJKSKLUJLUJLVKMVKMXKMD=@E>AE>AE>AD=@D=@C<?C<?B;>B;>B;>B;>IBEG@CC<?@9<=8:=8:>9;?:<=8:;8:@=?524:7" ascii
    $s8  = "VPTFFEI@FUSS@FC_VPXPWUIHQVS[PTTONXTQg]YHDNskh" fullword ascii
    $s9  = "Valeur Ecrite : " fullword ascii
    $s10 = "IJQIJOGHNFGMEFLDEB;>B;>B;>B;>B;>703:36?8;B;>C<?B;>?8;=69814925:36<58=69?8;@9<A:=?8;@9<A:=C<?E>AG@CIBEIBEHADG@CD=@B;>B;>D=@G@CHAD" ascii
    $s11 = "?:G<FABAABG@<@A8>9>9888@<?G9@@A@F8FA8@@8DG?A@89G<<E;=C?<D8@@8FC=GA:FB<GB9FG;BA8BOEFIG@KABKD@OGAM@@MGBOEBHEMHFIICOJGHL@HODNOCMKDI" ascii
    $s12 = "Size`xE" fullword ascii
    $s13 = "Copy node" fullword ascii
    $s14 = "Basic XML tester" fullword ascii
    $s15 = "<308:8@8<JINA@@988HAGHG@HD@H@DIDBLBBJFEICGB8C<==" fullword ascii
    $s16 = "@;<IDEA<==89FABHCDIDELGHKFGD?@IDED?@;67LGHC<?C<?C<?D=@D=@D=@E>AE>AD=@D=@" fullword ascii
    $s17 = "Value (string)" fullword ascii
    $s18 = "Node number" fullword ascii
    $s19 = "PAHI@HHBAOADH<@H@@L@GHB@J@@HDKSKIXHQXHPSMIJDHL@@PHOVNJPHJPHHRKKTHIPIHPHM@::D8<H8@HFBKABPBHPHJVMMPIPQHHHCBHCDHDHPHLRKLQJHRHHPNJSN" ascii
    $s20 = "Noeud source non existant dans ce fichier" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a410078918980fce320f92b4875de320" and (8 of them)
    ) or (all of them)
}