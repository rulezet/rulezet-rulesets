rule TTP_XOR_QUAD_CurrentVersionRun_3412 {
  strings:
    $key_3412 = { 67 7d [2] 43 73 [2] 68 5f [2] 46 7d [2] 52 66 [2] 5d 7c [2] 43 61 [2] 41 60 [2] 5a 66 [2] 46 61 [2] 5a 4e }

  condition:
    any of them
}