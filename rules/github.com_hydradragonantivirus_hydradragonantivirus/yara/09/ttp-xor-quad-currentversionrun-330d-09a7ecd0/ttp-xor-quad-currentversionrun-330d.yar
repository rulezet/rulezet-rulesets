rule TTP_XOR_QUAD_CurrentVersionRun_330d {
  strings:
    $key_330d = { 60 62 [2] 44 6c [2] 6f 40 [2] 41 62 [2] 55 79 [2] 5a 63 [2] 44 7e [2] 46 7f [2] 5d 79 [2] 41 7e [2] 5d 51 }

  condition:
    any of them
}