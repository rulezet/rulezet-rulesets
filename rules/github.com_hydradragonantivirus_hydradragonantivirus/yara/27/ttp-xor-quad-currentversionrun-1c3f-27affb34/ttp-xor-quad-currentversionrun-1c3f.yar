rule TTP_XOR_QUAD_CurrentVersionRun_1c3f {
  strings:
    $key_1c3f = { 4f 50 [2] 6b 5e [2] 40 72 [2] 6e 50 [2] 7a 4b [2] 75 51 [2] 6b 4c [2] 69 4d [2] 72 4b [2] 6e 4c [2] 72 63 }

  condition:
    any of them
}