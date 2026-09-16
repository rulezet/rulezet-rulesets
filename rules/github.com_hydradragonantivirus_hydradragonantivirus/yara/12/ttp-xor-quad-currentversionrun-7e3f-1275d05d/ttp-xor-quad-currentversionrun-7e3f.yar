rule TTP_XOR_QUAD_CurrentVersionRun_7e3f {
  strings:
    $key_7e3f = { 2d 50 [2] 09 5e [2] 22 72 [2] 0c 50 [2] 18 4b [2] 17 51 [2] 09 4c [2] 0b 4d [2] 10 4b [2] 0c 4c [2] 10 63 }

  condition:
    any of them
}