rule TTP_XOR_QUAD_CurrentVersionRun_153c {
  strings:
    $key_153c = { 46 53 [2] 62 5d [2] 49 71 [2] 67 53 [2] 73 48 [2] 7c 52 [2] 62 4f [2] 60 4e [2] 7b 48 [2] 67 4f [2] 7b 60 }

  condition:
    any of them
}