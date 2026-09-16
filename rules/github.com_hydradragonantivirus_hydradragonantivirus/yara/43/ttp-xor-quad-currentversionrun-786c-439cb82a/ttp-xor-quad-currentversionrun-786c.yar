rule TTP_XOR_QUAD_CurrentVersionRun_786c {
  strings:
    $key_786c = { 2b 03 [2] 0f 0d [2] 24 21 [2] 0a 03 [2] 1e 18 [2] 11 02 [2] 0f 1f [2] 0d 1e [2] 16 18 [2] 0a 1f [2] 16 30 }

  condition:
    any of them
}