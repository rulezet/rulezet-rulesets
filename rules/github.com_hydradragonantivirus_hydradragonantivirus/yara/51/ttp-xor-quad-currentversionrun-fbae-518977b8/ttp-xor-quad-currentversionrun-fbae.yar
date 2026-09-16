rule TTP_XOR_QUAD_CurrentVersionRun_fbae {
  strings:
    $key_fbae = { a8 c1 [2] 8c cf [2] a7 e3 [2] 89 c1 [2] 9d da [2] 92 c0 [2] 8c dd [2] 8e dc [2] 95 da [2] 89 dd [2] 95 f2 }

  condition:
    any of them
}