rule TTP_XOR_QUAD_CurrentVersionRun_ef3d {
  strings:
    $key_ef3d = { bc 52 [2] 98 5c [2] b3 70 [2] 9d 52 [2] 89 49 [2] 86 53 [2] 98 4e [2] 9a 4f [2] 81 49 [2] 9d 4e [2] 81 61 }

  condition:
    any of them
}