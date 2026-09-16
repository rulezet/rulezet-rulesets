rule TTP_XOR_QUAD_CurrentVersionRun_7dff {
  strings:
    $key_7dff = { 2e 90 [2] 0a 9e [2] 21 b2 [2] 0f 90 [2] 1b 8b [2] 14 91 [2] 0a 8c [2] 08 8d [2] 13 8b [2] 0f 8c [2] 13 a3 }

  condition:
    any of them
}