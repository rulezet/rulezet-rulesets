rule TTP_XOR_QUAD_CurrentVersionRun_3c1f {
  strings:
    $key_3c1f = { 6f 70 [2] 4b 7e [2] 60 52 [2] 4e 70 [2] 5a 6b [2] 55 71 [2] 4b 6c [2] 49 6d [2] 52 6b [2] 4e 6c [2] 52 43 }

  condition:
    any of them
}