rule win_vbs_rat_hworm

{
    meta:
        author = "Fidelis Cybersecurity"
        reference = "http://www.threatgeek.com/2016/11/down-the-h-w0rm-hole-with-houdinis-rat.html"
    strings:

                $sa1 = "CONFIG"

        $sa2 = "MYCODE"

        $sa3 = "SHELLOBJ.EXPANDENVIRONMENTSTRINGS"

        $sa4 = "BASE64TOHEX"

        $sa5 = "DCOM.VIRTUALALLOC"

        $sa6 = "LOADER_"

        $sa7 = "PE_PTR"

        $sa8 = "OBJWMISERVICE.EXECQUERY"

        $sa9 = "WSCRIPT.EXE" nocase

        $sa10 = "FUNCTION"

        $sa11 = "DIM"

        $sa12 = "END SUB"

                $sb1 = "HOST_FILE"

        $sb2 = "FILE_NAME"

        $sb3 = "INSTALL_DIR"

        $sb4 = "START_UP_REG"

        $sb5 = "START_UP_TASK"

        $sb6 = "START_UP_FOLDER"

        $sc1 = "DCOM_DATA"

        $sc2 = "LOADER_DATA"

        $sc3 = "FILE_DATA"

        $sc4 = "(1)"

        $sc5 = "(2)"

        $sc6 = "(3)"

        $sc7 = "FILE_SIZE"

    condition:

                (all of ($sa*)) and ( (all of ($sb*)) or (all of ($sc*)) )

}