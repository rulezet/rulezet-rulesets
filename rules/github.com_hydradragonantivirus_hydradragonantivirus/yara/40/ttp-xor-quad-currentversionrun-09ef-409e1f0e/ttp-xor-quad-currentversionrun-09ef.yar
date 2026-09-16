rule TTP_XOR_QUAD_CurrentVersionRun_09ef {
  strings:
    $key_09ef = { 5a 80 [2] 7e 8e [2] 55 a2 [2] 7b 80 [2] 6f 9b [2] 60 81 [2] 7e 9c [2] 7c 9d [2] 67 9b [2] 7b 9c [2] 67 b3 }

  condition:
    any of them
}