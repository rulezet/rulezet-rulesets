rule TTP_XOR_QUAD_CurrentVersionRun_d48a {
  strings:
    $key_d48a = { 87 e5 [2] a3 eb [2] 88 c7 [2] a6 e5 [2] b2 fe [2] bd e4 [2] a3 f9 [2] a1 f8 [2] ba fe [2] a6 f9 [2] ba d6 }

  condition:
    any of them
}