rule TTP_XOR_QUAD_CurrentVersionRun_786d {
  strings:
    $key_786d = { 2b 02 [2] 0f 0c [2] 24 20 [2] 0a 02 [2] 1e 19 [2] 11 03 [2] 0f 1e [2] 0d 1f [2] 16 19 [2] 0a 1e [2] 16 31 }

  condition:
    any of them
}