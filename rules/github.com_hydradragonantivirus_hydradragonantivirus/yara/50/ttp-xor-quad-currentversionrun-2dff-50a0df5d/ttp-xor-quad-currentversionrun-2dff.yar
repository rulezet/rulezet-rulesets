rule TTP_XOR_QUAD_CurrentVersionRun_2dff {
  strings:
    $key_2dff = { 7e 90 [2] 5a 9e [2] 71 b2 [2] 5f 90 [2] 4b 8b [2] 44 91 [2] 5a 8c [2] 58 8d [2] 43 8b [2] 5f 8c [2] 43 a3 }

  condition:
    any of them
}