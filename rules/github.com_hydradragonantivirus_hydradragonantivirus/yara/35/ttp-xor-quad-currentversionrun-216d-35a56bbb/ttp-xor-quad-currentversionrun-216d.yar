rule TTP_XOR_QUAD_CurrentVersionRun_216d {
  strings:
    $key_216d = { 72 02 [2] 56 0c [2] 7d 20 [2] 53 02 [2] 47 19 [2] 48 03 [2] 56 1e [2] 54 1f [2] 4f 19 [2] 53 1e [2] 4f 31 }

  condition:
    any of them
}