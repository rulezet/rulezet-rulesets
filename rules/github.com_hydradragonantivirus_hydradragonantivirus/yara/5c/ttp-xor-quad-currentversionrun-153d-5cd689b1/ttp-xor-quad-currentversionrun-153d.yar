rule TTP_XOR_QUAD_CurrentVersionRun_153d {
  strings:
    $key_153d = { 46 52 [2] 62 5c [2] 49 70 [2] 67 52 [2] 73 49 [2] 7c 53 [2] 62 4e [2] 60 4f [2] 7b 49 [2] 67 4e [2] 7b 61 }

  condition:
    any of them
}