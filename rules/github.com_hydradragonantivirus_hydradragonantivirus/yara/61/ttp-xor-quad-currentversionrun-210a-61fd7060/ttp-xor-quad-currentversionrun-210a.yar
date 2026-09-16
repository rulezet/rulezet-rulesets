rule TTP_XOR_QUAD_CurrentVersionRun_210a {
  strings:
    $key_210a = { 72 65 [2] 56 6b [2] 7d 47 [2] 53 65 [2] 47 7e [2] 48 64 [2] 56 79 [2] 54 78 [2] 4f 7e [2] 53 79 [2] 4f 56 }

  condition:
    any of them
}