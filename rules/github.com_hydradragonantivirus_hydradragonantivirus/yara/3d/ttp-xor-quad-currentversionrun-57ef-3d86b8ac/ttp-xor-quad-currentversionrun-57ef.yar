rule TTP_XOR_QUAD_CurrentVersionRun_57ef {
  strings:
    $key_57ef = { 04 80 [2] 20 8e [2] 0b a2 [2] 25 80 [2] 31 9b [2] 3e 81 [2] 20 9c [2] 22 9d [2] 39 9b [2] 25 9c [2] 39 b3 }

  condition:
    any of them
}