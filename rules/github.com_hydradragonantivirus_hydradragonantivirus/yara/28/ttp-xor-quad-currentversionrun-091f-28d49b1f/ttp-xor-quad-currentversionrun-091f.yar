rule TTP_XOR_QUAD_CurrentVersionRun_091f {
  strings:
    $key_091f = { 5a 70 [2] 7e 7e [2] 55 52 [2] 7b 70 [2] 6f 6b [2] 60 71 [2] 7e 6c [2] 7c 6d [2] 67 6b [2] 7b 6c [2] 67 43 }

  condition:
    any of them
}