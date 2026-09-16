rule TTP_XOR_QUAD_CurrentVersionRun_673f {
  strings:
    $key_673f = { 34 50 [2] 10 5e [2] 3b 72 [2] 15 50 [2] 01 4b [2] 0e 51 [2] 10 4c [2] 12 4d [2] 09 4b [2] 15 4c [2] 09 63 }

  condition:
    any of them
}