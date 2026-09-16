rule TTP_XOR_QUAD_CurrentVersionRun_0382 {
  strings:
    $key_0382 = { 50 ed [2] 74 e3 [2] 5f cf [2] 71 ed [2] 65 f6 [2] 6a ec [2] 74 f1 [2] 76 f0 [2] 6d f6 [2] 71 f1 [2] 6d de }

  condition:
    any of them
}