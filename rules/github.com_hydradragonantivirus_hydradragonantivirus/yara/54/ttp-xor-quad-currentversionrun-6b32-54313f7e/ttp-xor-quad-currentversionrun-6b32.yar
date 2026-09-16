rule TTP_XOR_QUAD_CurrentVersionRun_6b32 {
  strings:
    $key_6b32 = { 38 5d [2] 1c 53 [2] 37 7f [2] 19 5d [2] 0d 46 [2] 02 5c [2] 1c 41 [2] 1e 40 [2] 05 46 [2] 19 41 [2] 05 6e }

  condition:
    any of them
}