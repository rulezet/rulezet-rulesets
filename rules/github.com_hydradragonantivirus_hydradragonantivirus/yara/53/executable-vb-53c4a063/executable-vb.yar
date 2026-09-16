rule executable_vb {
  meta:
    is_exe    = true
    revision  = "100"
    rank      = 10
    type      = "vb"
    date      = "July 29 2015"
    author    = "@tylabs"
    copyright = "QuickSand.io 2015"
    tlp       = "green"

  strings:
    $s1 = "impersonationLevel=impersonate"
    $s2 = "On Error Resume Next"
    $s3 = "WScript.CreateObject(\"WScript.Shell\")"
    $s4 = "CreateObject(\"Scripting.FileSystemObject\")"

  condition:
    1 of them
}