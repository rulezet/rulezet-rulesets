import "pe"
rule _codeCrypter_031__Tibbar_ {
  meta:
    description = "codeCrypter 0.31 -> Tibbar"

  strings:
    $0 = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

  condition:
    $0 at pe.entry_point
}