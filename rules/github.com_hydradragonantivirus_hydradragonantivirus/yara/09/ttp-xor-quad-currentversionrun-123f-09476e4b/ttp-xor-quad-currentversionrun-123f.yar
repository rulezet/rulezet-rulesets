rule TTP_XOR_QUAD_CurrentVersionRun_123f {
  strings:
    $key_123f = { 41 50 [2] 65 5e [2] 4e 72 [2] 60 50 [2] 74 4b [2] 7b 51 [2] 65 4c [2] 67 4d [2] 7c 4b [2] 60 4c [2] 7c 63 }

  condition:
    any of them
}