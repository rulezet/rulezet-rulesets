rule sig_20170125_41de50a7449d34cf6ccc3bd1d4467095 {
  meta:
    description = "datamaliciousorder - file 20170125_41de50a7449d34cf6ccc3bd1d4467095.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8d43fe186007eb6c7b91505e608affb6398855ea24e046283dc41c57feb12c8"

  strings:
    $s1  = "//var ilqixhodh = odtuvmog[lmemjuqiqnatpigrymamogfikfexkehykvofjehmequnywubwehpingywyfamixciqledvocorygcuxpapicbi()[[ /*em*/ , 0" ascii
    $s2  = "//if (ilqixhodh[xdofwibnewepnamgogfydcebewnogokqokgebrugzuqyvydorawuhizsahazqakgomis()[[ /*qgaxp*/ , /*rbyle*/ , /*fzej*/ , 3][3" ascii
    $s3  = "rbicgyno[irbakajabanetyxalvuhurorretotaxahhusukaffemxipaqwiriqiwubifvybaxokynrocomaxmoqpa()[[ /*ogc*/ , /*ccecq*/ , 2, /*abelj*/" ascii
    $s4  = "var ygixj = ofwomlivqigahdepefanpycvajwigconsajkyllypxenaqypebacoqejofhydqaxecgelulurytmetxiglobozybabokxuqqucyvytde()[kvexhidtu" ascii
    $s5  = "bibvygokwunoccujjyvifvagubogepazpirn()[[ /*luke*/ , 0, /*jgewe*/ , /*uba*/ ][1]] + lxehcomjaqvufbuwagtawopavyxokygobfabibgajkume" ascii
    $s6  = "mucqopby()[[ /*fell*/ , 3, /*ykx*/ ][1]] + borqetalobzefopbawpyhxemecmeppedelibabdislujcekfyksibnaqowpyqbasnewlytcomhajorfabuse(" ascii
    $s7  = "return [ /*gwaxu*/ , /*kyv*/ , \"C:\\\\\", /*laxtu*/ ];" fullword ascii
    $s8  = "return [ /*gty*/ , /*gi*/ , /*xe*/ , WScript, /*jopi*/ , /*epovm*/ ][3];" fullword ascii
    $s9  = "function fkumegelacugymmyqfysvozwejopxybjatgusenulogagzajqenfymwidevkugevkachyvecdezyvjanqulfazxa() {" fullword ascii
    $s10 = "function almecopqemicypfoqakresliwozgiwqodybifcegdelwogtulragzihpuqdogwobulogwutfozw() {" fullword ascii
    $s11 = "function vibulledufxuhvilzelutlyvzonbyndihizrugemegbizcircibgerocisexlyqoqdeftovzogs() {" fullword ascii
    $s12 = "function jebiqubynvajadxofevemotoftacguspyxboxedoxvukexusytaqypvokpobra() {" fullword ascii
    $s13 = "function uhiwequroqupacohkylgyxfuqubjizapwaziqabalexetomgypkugjimircydyn() {" fullword ascii
    $s14 = "return [ /*emginn*/ , \"Get\", /*traqva*/ , /*ejalk*/ ];" fullword ascii
    $s15 = "rqoqeqyzuletitojmafojixbejlewegqelufjitnocsem()[[ /*yle*/ , 0, /*joke*/ , /*nhi*/ , /*ici*/ ][1]] + ohahlagzumsycsibvyjitykenyzb" ascii
    $s16 = "*qtuzcu*/ , /*lwi*/ , 0, /*lowy*/ ][3]] + axrijkibacuwutdokzevawevypgykxybuwmuqhehpiruvsugjygeguzummotybicdexyrgajkypupibydq()[[" ascii
    $s17 = "function udtyqjitunynnyfsehaqjobmalbintozaxotgylluklylxitvonackyqylqydiwzewevqelvuxraqamwivu() {" fullword ascii
    $s18 = "function borqetalobzefopbawpyhxemecmeppedelibabdislujcekfyksibnaqowpyqbasnewlytcomhajorfabuse() {" fullword ascii
    $s19 = "function lxehcomjaqvufbuwagtawopavyxokygobfabibgajkumematavlordyjxukoquzezsegizivwinn() {" fullword ascii
    $s20 = "function mulzazmiwkiftysnyqywarmebobinykeblidfiqdybzolsajosyqgiwkijivmekzynogsehqeqybuk() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}