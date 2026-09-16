rule TTP_XOR_QUAD_CurrentVersionRun_786f {
  strings:
    $key_786f = { 2b 00 [2] 0f 0e [2] 24 22 [2] 0a 00 [2] 1e 1b [2] 11 01 [2] 0f 1c [2] 0d 1d [2] 16 1b [2] 0a 1c [2] 16 33 }

  condition:
    any of them
}