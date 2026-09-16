rule hacktool_windows_cobaltstrike_beacon
{
    meta:
        description = "Detection of the Beacon payload from Cobalt Strike"
        reference = "https://www.cobaltstrike.com/help-beacon"
        author = "@javutin, @joseselvi"
    condition:
        cobaltstrike_beacon_b64 or
        cobaltstrike_beacon_raw or
        cobaltstrike_beacon_exe
}