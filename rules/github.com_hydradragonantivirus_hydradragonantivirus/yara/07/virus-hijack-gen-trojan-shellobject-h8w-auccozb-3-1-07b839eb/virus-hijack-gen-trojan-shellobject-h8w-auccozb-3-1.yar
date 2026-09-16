rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_auCCoZb_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7da8151aae38faa10b8f20bb012b4c3a403f0624c1c9600f42aea2f29bdcbc42"

  strings:
    $s1 = "Memuzujib tawikojonusep bevonofaxed worovogadinaz. Jojoje legomagohofaku hipivakoradoki yoyima vez. Nicebunekayido. Golepi dugup" ascii
    $s2 = "Tucoha towo. Dadulasopibi wafisanu loge pijigig. Zepubaruyifiyo nakel lesudaworu. Dehisiho cixo. Lakasayaha nawuluxex. Joxazifax" ascii
    $s3 = "Pejakufujujaga pidekuwanehe setiyadilak dibetosekuf jasol. Bofayugi jacadalot. Fumekunesixo. Xohipovagajem diwador kezahuba heva" ascii
    $s4 = "Fevufa pehalizep vagag.Yule hetilok hetor vemokapiku gedexu yetoj xuw[Kacebimere bixelexag xama wohirexezekam setuviluxasux fame" wide
    $s5 = "bej gagamikoves vefecomapogaho. Kosu sovekar. Mulajime. Malu. Kulewu tayoyutaxu faro wexaxicegefevuh jewubomude. Bipomidojuyopaz" ascii
    $s6 = "ux kizemohecuwuh. Cora wugoyijatebu nuhoziseren. Rovemezahugos xelijasa hafufazusito. Bomanitihicumek focolipibixani cinawoli. X" ascii
    $s7 = ". Jadaxawihozaw yahekayefuhe. Jazehikajacum buwusezuw sav wazoha xiveyajovajizig. Jen votodop. Guru. Wokutereh xelaregelapov xat" ascii
    $s8 = "ame xazeri. Jitegovad negib pohagejayar. Negux. Bena calajugumufet tucup lofefi famecohasajoy. Rez. Yefecorulu zikafaduxi. Begor" ascii
    $s9 = "Letifim bunaxe litolekufumiga^Cugig vavopeka wipujomamidexir wesaguh cajoyune derebex zifag pafineku mapewewosaxo telojocamo3Mac" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}