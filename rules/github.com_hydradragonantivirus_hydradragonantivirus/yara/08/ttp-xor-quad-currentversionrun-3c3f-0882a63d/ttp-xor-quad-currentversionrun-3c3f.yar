rule TTP_XOR_QUAD_CurrentVersionRun_3c3f {
  strings:
    $key_3c3f = { 6f 50 [2] 4b 5e [2] 60 72 [2] 4e 50 [2] 5a 4b [2] 55 51 [2] 4b 4c [2] 49 4d [2] 52 4b [2] 4e 4c [2] 52 63 }

  condition:
    any of them
}