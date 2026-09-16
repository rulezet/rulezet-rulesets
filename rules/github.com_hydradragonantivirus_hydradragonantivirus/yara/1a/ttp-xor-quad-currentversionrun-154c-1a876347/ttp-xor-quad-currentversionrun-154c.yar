rule TTP_XOR_QUAD_CurrentVersionRun_154c {
  strings:
    $key_154c = { 46 23 [2] 62 2d [2] 49 01 [2] 67 23 [2] 73 38 [2] 7c 22 [2] 62 3f [2] 60 3e [2] 7b 38 [2] 67 3f [2] 7b 10 }

  condition:
    any of them
}