rule TTP_XOR_QUAD_CurrentVersionRun_080a {
  strings:
    $key_080a = { 5b 65 [2] 7f 6b [2] 54 47 [2] 7a 65 [2] 6e 7e [2] 61 64 [2] 7f 79 [2] 7d 78 [2] 66 7e [2] 7a 79 [2] 66 56 }

  condition:
    any of them
}