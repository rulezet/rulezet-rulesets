rule TTP_XOR_QUAD_CurrentVersionRun_3f8a {
  strings:
    $key_3f8a = { 6c e5 [2] 48 eb [2] 63 c7 [2] 4d e5 [2] 59 fe [2] 56 e4 [2] 48 f9 [2] 4a f8 [2] 51 fe [2] 4d f9 [2] 51 d6 }

  condition:
    any of them
}