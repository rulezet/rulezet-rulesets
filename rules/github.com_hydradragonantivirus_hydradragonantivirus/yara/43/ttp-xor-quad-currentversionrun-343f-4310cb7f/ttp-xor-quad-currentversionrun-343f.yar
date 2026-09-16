rule TTP_XOR_QUAD_CurrentVersionRun_343f {
  strings:
    $key_343f = { 67 50 [2] 43 5e [2] 68 72 [2] 46 50 [2] 52 4b [2] 5d 51 [2] 43 4c [2] 41 4d [2] 5a 4b [2] 46 4c [2] 5a 63 }

  condition:
    any of them
}