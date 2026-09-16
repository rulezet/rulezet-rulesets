rule TTP_XOR_QUAD_CurrentVersionRun_fef2 {
  strings:
    $key_fef2 = { ad 9d [2] 89 93 [2] a2 bf [2] 8c 9d [2] 98 86 [2] 97 9c [2] 89 81 [2] 8b 80 [2] 90 86 [2] 8c 81 [2] 90 ae }

  condition:
    any of them
}