rule TTP_XOR_QUAD_CurrentVersionRun_573f {
  strings:
    $key_573f = { 04 50 [2] 20 5e [2] 0b 72 [2] 25 50 [2] 31 4b [2] 3e 51 [2] 20 4c [2] 22 4d [2] 39 4b [2] 25 4c [2] 39 63 }

  condition:
    any of them
}