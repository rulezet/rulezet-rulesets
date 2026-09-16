rule XProtect_BUNDLORE_resource_fork {
  meta:
    description = "MACOS.BUNDLORE.SCRIPT"

  strings:
    $shebang       = "#!"
    $resource_fork = "$0/..namedfork/rsrc" fullword
    $tail          = "tail -c" fullword

  condition:
    $shebang at 0 and
    all of them
}