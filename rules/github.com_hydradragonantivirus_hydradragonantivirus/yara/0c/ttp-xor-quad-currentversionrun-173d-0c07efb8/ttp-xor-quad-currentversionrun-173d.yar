rule TTP_XOR_QUAD_CurrentVersionRun_173d {
  strings:
    $key_173d = { 44 52 [2] 60 5c [2] 4b 70 [2] 65 52 [2] 71 49 [2] 7e 53 [2] 60 4e [2] 62 4f [2] 79 49 [2] 65 4e [2] 79 61 }

  condition:
    any of them
}