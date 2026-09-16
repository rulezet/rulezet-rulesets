rule TTP_XOR_QUAD_CurrentVersionRun_383f {
  strings:
    $key_383f = { 6b 50 [2] 4f 5e [2] 64 72 [2] 4a 50 [2] 5e 4b [2] 51 51 [2] 4f 4c [2] 4d 4d [2] 56 4b [2] 4a 4c [2] 56 63 }

  condition:
    any of them
}