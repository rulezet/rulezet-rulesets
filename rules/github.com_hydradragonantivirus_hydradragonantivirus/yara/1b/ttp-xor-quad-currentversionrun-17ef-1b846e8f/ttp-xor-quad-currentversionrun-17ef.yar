rule TTP_XOR_QUAD_CurrentVersionRun_17ef {
  strings:
    $key_17ef = { 44 80 [2] 60 8e [2] 4b a2 [2] 65 80 [2] 71 9b [2] 7e 81 [2] 60 9c [2] 62 9d [2] 79 9b [2] 65 9c [2] 79 b3 }

  condition:
    any of them
}