rule TTP_XOR_QUAD_CurrentVersionRun_502f {
  strings:
    $key_502f = { 03 40 [2] 27 4e [2] 0c 62 [2] 22 40 [2] 36 5b [2] 39 41 [2] 27 5c [2] 25 5d [2] 3e 5b [2] 22 5c [2] 3e 73 }

  condition:
    any of them
}