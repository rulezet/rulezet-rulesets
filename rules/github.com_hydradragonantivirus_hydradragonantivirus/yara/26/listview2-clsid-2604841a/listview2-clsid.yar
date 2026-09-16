rule ListView2_CLSID {
  meta:
    author = "Didier Stevens (https://DidierStevens.com)"

  strings:
    $a1 = { 4B F0 D1 BD 8B 85 D1 11 B1 6A 00 C0 F0 28 36 28 }

  condition:
    any of them
}