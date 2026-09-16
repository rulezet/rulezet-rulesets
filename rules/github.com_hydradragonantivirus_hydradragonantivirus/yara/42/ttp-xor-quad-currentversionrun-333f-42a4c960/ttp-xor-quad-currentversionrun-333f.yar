rule TTP_XOR_QUAD_CurrentVersionRun_333f {
  strings:
    $key_333f = { 60 50 [2] 44 5e [2] 6f 72 [2] 41 50 [2] 55 4b [2] 5a 51 [2] 44 4c [2] 46 4d [2] 5d 4b [2] 41 4c [2] 5d 63 }

  condition:
    any of them
}