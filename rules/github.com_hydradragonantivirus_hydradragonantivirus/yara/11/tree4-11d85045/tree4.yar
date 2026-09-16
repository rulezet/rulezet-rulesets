rule tree4 {
  strings:
    $s0    = "addMethodprotocol" fullword
    $s1    = "registerClassPair" fullword
    $s2    = "sSD10FoundationE19" fullword
    $s3    = "ZN10cryptonote35absolute" fullword
    $s4    = "HEHEHEHEHEHEHEHE" fullword
    $s5    = "getblocktemplate" fullword
    $s6    = "welcomeScreenIdentifier" fullword
    $s7    = "setStandardInput" fullword
    $s8    = "140213191008Z0A1" fullword
    $s9    = "fileHandleForWriting" fullword
    $s10   = "ZBSystemInformation" fullword
    $s11   = "stopStatusIconAnimation" fullword
    $s12   = "supportsUIRestoring" fullword
    $s13   = "20191105000000Z0" fullword
    $s14   = "ZN6Common9JsonValue3setERKNSt3" fullword
    $s15   = "navigationBarNodeSortingOrder" fullword
    $s16   = "IORegistryEntryFromPath" fullword
    $s17   = "EnterModifiedCompliance" fullword
    $s18   = "insertStatisticEvent" fullword
    $s19   = "removeScannedItem" fullword
    $s20   = "addUndeleterFilesRecovered" fullword
    $s21   = "applicationDockMenu" fullword
    $s22   = "140129192647Z0A1" fullword
    $s23   = "11checkObjectERKNSt3" fullword
    $s24   = "setStandardOutput" fullword
    $s25   = "errorWithNECErrorCode" fullword
    $s26   = "didFinishLoadingNavigation" fullword
    $s27   = "12CrtAllocatorELj0EE12PrettyPrefixENS" fullword
    $s28   = "ponponqqtsrtsruuxwvwvyy" fullword
    $s29   = "initWithHelperID" fullword
    $s30   = "autoreleaseReturnValue" fullword
    $s31   = "ZN26DbMultipleRecnoDataBuilderC2ER3Dbt" fullword
    $s32   = "newVersionAvailable" fullword
    $s33   = "350209214036Z0b1" fullword
    $s34   = "15mutex6unlockEv" fullword
    $s35   = "setMinimumContentSize" fullword
    $s36   = "stateEE5resetISN" fullword
    $s37   = "generationComplete" fullword
    $s38   = "HEHEHEHEHEHEHEHEHEHEHEHEHELuI" fullword
    $s39   = "ZN9QListData11shared" fullword
    $s40   = "ApplicationServices" fullword
    $s41   = "retainAutoreleasedReturnValue" fullword
    $s42   = "NSAutoreleasePool" fullword
    $s43   = "KhfCECHKJKnKtDkW" fullword
    $s44   = "willEncodeRestorableStateWithCoder" fullword
    $s45   = "0123456789abcdef" fullword
    $s46   = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s47   = "ddddddddddddddddddddddddddddddddsd" fullword
    $s48   = "SystemConfiguration" fullword
    $s50   = "DefaultRuneLocale" fullword
    $s51   = "enumerationMutation" fullword
    $s53   = "CFStringGetCString" fullword
    $s54   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s55   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s56   = "CGPathCreateMutable" fullword
    $s57   = "logKextUserClient" fullword
    $s58   = "numberWithDouble" fullword
    $s59   = "stringWithString" fullword
    $s60   = "HMHMHMHMHMHMHMHMH" fullword
    $s61   = "ZTSN5boost9exceptionE" fullword
    $s62   = "autoreleasePoolPop" fullword
    $s63   = "dataWithContentsOfFile" fullword
    $s64   = "MobileCoreServices" fullword
    $s65   = "lswiftObjectiveC" fullword
    $s66   = "HEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEgqV" fullword
    $s67   = "IOServiceGetMatchingServices" fullword
    $s68   = "NSNotificationCenter" fullword
    $s69   = "fileExistsAtPath" fullword
    $s70   = "EHMHMHMHMHMHMHMH" fullword
    $s71   = "AuthorizationFree" fullword
    $s72   = "arrayWithObjects" fullword
    $s73   = "UHAWAVAUATSHHHuE" fullword
    $s74   = "JSObjectSetProperty" fullword
    $s75   = "FromStringAndSize" fullword
    $s76   = "CFStringCreateWithCString" fullword
    $s77   = "ZL30NSUndoManagerProxy" fullword
    $s78   = "DEDEDEDEDEDEDEDE9E" fullword
    $s79   = "PrivateFrameworks" fullword
    $s80   = "CFArrayGetValueAtIndex" fullword
    $s82   = "OSAtomicDecrement32" fullword
    $s83   = "CFConstantStringClassReference" fullword
    $s84   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s85   = "NSAddressOfSymbol" fullword
    $s86   = "iPhoneSimulator10" fullword
    $s87   = "ZN9QListData7disposeEPNS" fullword
    $s88   = "NSConcreteGlobalBlock" fullword
    $s89   = "localizedStringForKey" fullword
    $s90   = "debugDescription" fullword
    $s93   = "libswiftDispatch" fullword
    $s94   = "NSStringFromClass" fullword
    $s101  = "retainAutorelease" fullword
    $s119  = "9allocatorIcEEEC1ERKS5" fullword
    $s120  = "componentsSeparatedByString" fullword
    $s121  = "kCFAllocatorDefault" fullword
    $s122  = "ellipticcurvelist" fullword
    $s123  = "initWithIdentifier" fullword
    $s126  = "stringWithFormat" fullword
    $s127  = "ZN16QLoggingCategoryD1Ev" fullword
    $s128  = "CFBundleIdentifier" fullword
    $s130  = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s131  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s132  = "ServiceManagement" fullword
    $s136  = "UHAWAVAUATSPIHIH" fullword
    $s137  = "copyElephantBrain" fullword
    $s140  = "createFileAtPath" fullword
    $s143  = "sqhIJsyyeFaPcYe7" fullword
    $s145  = "replaceCharactersInRange" fullword
    $s147  = "HMHMHMHMHMHMHMHML" fullword
    $s149  = "DisableThreadLibraryCalls" fullword
    $s150  = "traitsIcEEE3putEc" fullword
    $s173  = "getInitializedObjCClass" fullword
    $s174  = "UIViewController" fullword
    $s175  = "category23default" fullword
    $s176  = "SecItemCopyMatching" fullword
    $s178  = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s253  = "resignFirstResponder" fullword
    $s254  = "NSAssertionHandler" fullword
    $s265  = "CFRunLoopGetMain" fullword
    $s267  = "replacementString" fullword
    $s268  = "spDkrKTDKFCLC8CXD" fullword
    $s269  = "ShCsSwSzfKpADKfADCNK" fullword
    $s280  = "respondsToSelector" fullword
    $s281  = "CFNumberGetValue" fullword
    $s282  = "stringWithUTF8String" fullword
    $s286  = "CGContextFillPath" fullword
    $s290  = "completionHandler" fullword
    $s291  = "forKeyedSubscriptP19NSMutableDictionaryP13objc" fullword
    $s294  = "NSOperationQueue" fullword
    $s295  = "systemFontOfSize" fullword
    $s298  = "libswiftCoreFoundation" fullword
    $s299  = "9allocatorIcEEEE" fullword
    $s300  = "CFBundleInfoDictionaryVersion" fullword
    $s301  = "libswiftCoreGraphics" fullword
    $s302  = "getExistentialTypeMetadata" fullword
    $s303  = "IOIteratorIsValid" fullword
    $s304  = "getInstanceMethod" fullword
    $s308  = "contentsOfDirectoryAtPath" fullword
    $s314  = "alSourceQueueBuffers" fullword
    $s317  = "IOConnectMapMemory" fullword
    $s318  = "traitsIcEEE9showmanycEv" fullword
    $s319  = "certverifyresult" fullword
    $s320  = "UHAWAVAUATSH8IHuIH" fullword
    $s321  = "UHAWAVAUATSH8IIH" fullword
    $s322  = "getImplementation" fullword
    $s323  = "UHAWAVAUATSH8HIH" fullword
    $s326  = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s327  = "ecpointformatlist" fullword
    $s329  = "UHAWAVAUATSPIHIIH" fullword
    $s330  = "UHAWAVAUATSPAAII" fullword
    $s331  = "NSFetchedPropertyDescription" fullword
    $s332  = "CFStringMakeConstantString" fullword
    $s333  = "CFURLGetFileSystemRepresentation" fullword
    $s393  = "UIApplicationDelegate" fullword
    $s394  = "NSMutableURLRequest" fullword
    $s398  = "sharedApplication" fullword
    $s402  = "UHAWAVAUATSH8IIHH" fullword
    $s407  = "UHAWAVAUATSH8IHH" fullword
    $s415  = "UHAWAVAUATSPAIIB" fullword
    $s451  = "CGContextFillRect" fullword
    $s464  = "UHAWAVAUATSPIIHt" fullword
    $s465  = "bundleIdentifier" fullword
    $s466  = "dictionaryWithContentsOfFile" fullword
    $s469  = "NSMutableOrderedSet" fullword
    $s472  = "N5boost9gregorian15bad" fullword
    $s473  = "CGRectContainsPoint" fullword
    $s476  = "clickedButtonAtIndex" fullword
    $s477  = "didFinishDownloadingToURL" fullword
    $s484  = "GetEnvironmentVariable" fullword
    $s486  = "gestureRecognizer" fullword
    $s492  = "StringCharCodeAt" fullword
    $s498  = "glFramebufferTextureLayer" fullword
    $s499  = "GenerateConnectionID" fullword
    $s505  = "mediumspringgreen" fullword
    $s506  = "AECreateAppleEvent" fullword
    $s564  = "SMSTSoSSSSSSSS7U" fullword
    $s565  = "arrayWithCapacity" fullword
    $s566  = "CFDictionaryCreateMutable" fullword
    $s568  = "conformsToProtocol" fullword
    $s572  = "UserNotifications" fullword
    $s573  = "reachabilityWithHostName" fullword
    $s579  = "ImageCaptureCore" fullword
    $s609  = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s610  = "selectorPFP11objc" fullword
    $s611  = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s613  = "NetworkExtension" fullword
    $s625  = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s661  = "CFURLCopyFileSystemPath" fullword
    $s667  = "componentsJoinedByString" fullword
    $s671  = "N5boost9exceptionE" fullword
    $s672  = "constants10error" fullword
    $s673  = "encodeURIComponent" fullword
    $s674  = "linenoiseEditMoveRight" fullword
    $s692  = "userInterfaceIdiom" fullword
    $s700  = "removeObjectForKey" fullword
    $s701  = "JKDictionaryClass" fullword
    $s714  = "UHAWAVAUATSPILuI" fullword
    $s716  = "applicationDidResignActive" fullword
    $s717  = "initWithCapacity" fullword
    $s718  = "CGContextStrokePath" fullword
    $s723  = "CFBundleCopyResourceURL" fullword
    $s724  = "countByEnumeratingWithState" fullword
    $s728  = "djwIcRRRRRRRRRRRRRRK" fullword
    $s729  = "caseInsensitiveCompare" fullword
    $s742  = "traitsIcEEE5tellgEv" fullword
    $s743  = "kMDItemWhereFroms" fullword
    $s762  = "NSRunningApplication" fullword
    $s763  = "NSPropertyListSerialization" fullword
    $s803  = "ZN9QListData6appendERKS" fullword
    $s829  = "LSGetCurrentApplicationASN" fullword
    $s832  = "9allocatorIcEEEEPNS0" fullword
    $s834  = "ZN5boost2io6detail13call" fullword
    $s835  = "ZTVN5boost4asio5error6detail12ssl" fullword
    $s836  = "ZTSN5boost18thread" fullword
    $s853  = "gSearchProviderUrl" fullword
    $s854  = "JavaApplicationStub" fullword
    $s855  = "TpEQULved3Ly7GqqbjLfo6hqMSo" fullword
    $s856  = "b77a5c561934e089" fullword
    $s857  = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s858  = "enumerateObjectsUsingBlock" fullword
    $s859  = "calcDecodeLength" fullword
    $s860  = "UHAWAVAUATSPIIIu0Ht" fullword
    $s863  = "includingPropertiesForKeys" fullword
    $s865  = "IOHIDElementGetLogicalMax" fullword
    $s868  = "setPreferredContentSize" fullword
    $s870  = "20160507105842Z0" fullword
    $s871  = "stringByAppendingPathComponent" fullword
    $s872  = "CFBundleCopyBundleURL" fullword
    $s874  = "dataUsingEncoding" fullword
    $s877  = "210412223435Z0V1" fullword
    $s883  = "certificateauthority0" fullword
    $s884  = "140305162647Z0A1" fullword
    $s885  = "270201221215Z0y1" fullword
    $s888  = "certificateauthority" fullword
    $s903  = "200219223002Z0B1" fullword
    $s955  = "runningApplications" fullword
    $s958  = "getGenericMetadata1" fullword
    $s963  = "CFBundleShortVersionString" fullword
    $s967  = "kCFCoreFoundationVersionNumber" fullword
    $s975  = "queuedCrashReportDirectory" fullword
    $s979  = "certificationauthority" fullword
    $s982  = "traitsIcEEEEE16find" fullword
    $s986  = "ZN5boost19thread" fullword
    $s994  = "substringToIndex" fullword
    $s1005 = "N5boost6detail11thread" fullword
    $s1013 = "UHAWAVAUATSHhMMIH" fullword
    $s1047 = "UHAWAVAUATSPIIID" fullword
    $s1048 = "crossCertificatePair" fullword
    $s1076 = "20191001103003Z0" fullword
    $s1083 = "USBInterfaceOpen" fullword
    $s1089 = "CGContextRelease" fullword
    $s1090 = "operatingSystemVersionString" fullword
    $s1102 = "SecStaticCodeCreateWithPath" fullword
    $s1109 = "viewForHeaderInSection" fullword
    $s1111 = "setCanChooseDirectories" fullword
    $s1116 = "showPageWithIndex" fullword
    $s1130 = "textDidEndEditing" fullword
    $s1131 = "dictionaryWithJSONString" fullword
    $s1148 = "inManagedObjectContext" fullword
    $s1153 = "didUpdateUserActivity" fullword
    $s1162 = "DUHAWAVAUATSPIII" fullword
    $s1175 = "getCursorPosition" fullword
    $s1180 = "numberWithUnsignedLong" fullword
    $s1182 = "retainAutoreleaseReturnValue" fullword
    $s1183 = "continueUserActivity" fullword
    $s1184 = "IOServiceTerminate" fullword
    $s1193 = "ARCLiteIndexedSubscripting" fullword
    $s1198 = "timeIntervalSinceDate" fullword
    $s1202 = "initWithContentsOfURL" fullword
    $s1204 = "shouldHighlightRowAtIndexPath" fullword
    $s1214 = "loadWeakRetained" fullword
    $s1215 = "uriuwfgjZasjXjjgZg" fullword
    $s1229 = "stringWithCapacity" fullword
    $s1231 = "ZBUSystemInformation" fullword
    $s1257 = "connectionDidFinishLoading" fullword
    $s1258 = "NSUndoManagerProxy" fullword
    $s1259 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1261 = "scheduledTimerWithTimeInterval" fullword
    $s1264 = "G16ComparisonResultOtF" fullword
    $s1265 = "didFailToContinueUserActivityWithType" fullword
    $s1286 = "numberWithUnsignedInt" fullword
    $s1294 = "removeCustomView" fullword
    $s1297 = "withIntermediateDirectories" fullword
    $s1299 = "viewForTableColumn" fullword
    $s1306 = "cancelAllOperations" fullword
    $s1313 = "RARARARARARARARARARAZAp" fullword
    $s1318 = "objectForKeyP11objc" fullword
    $s1327 = "replaceObjectAtIndex" fullword
    $s1337 = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s1349 = "isItemExpandable" fullword
    $s1350 = "dataWithJSONObject" fullword
    $s1356 = "applicationShouldHandleReopen" fullword
    $s1358 = "ASASASASASASASASASASB" fullword
    $s1371 = "ZBNTFSVolumeScanner" fullword
    $s1372 = "onAllAppsChanged" fullword
    $s1373 = "ZBLocalizedString" fullword
    $s1376 = "getAuthorization" fullword
    $s1380 = "lengthOfBytesUsingEncoding" fullword
    $s1385 = "setDefaultsDomain" fullword
    $s1401 = "willResizeForVersionBrowserWithMaxPreferredSize" fullword
    $s1402 = "setAutosaveExpandedItems" fullword
    $s1421 = "formatsIcE27duration" fullword
    $s1432 = "applicationWillHide" fullword
    $s1434 = "kSMDomainSystemLaunchd" fullword
    $s1447 = "IOPlatformExpertDevice" fullword
    $s1454 = "IntermediateBuildFilesPath" fullword
    $s1455 = "initializeClassPair" fullword
    $s1456 = "fileHandleForReading" fullword
    $s1459 = "addEntriesFromDictionaryP11objc" fullword
    $s1462 = "HuHhHEHpHMHpHEHuH" fullword
    $s1472 = "performActionForShortcutItem" fullword
    $s1480 = "autoreleasepoolPK11mach" fullword
    $s1481 = "collectingEnabled" fullword
    $s1494 = "applyMacKeeperFlatDesign" fullword
    $s1495 = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s1497 = "setInstanceVariableP11objc" fullword
    $s1501 = "getRequiredClass" fullword
    $s1502 = "L9LOLbLlLzLLLLLbLLLLLLLLLL" fullword
    $s1519 = "setInvalidationHandler" fullword
    $s1529 = "delegateHandlesKey" fullword
    $s1531 = "NSURLSessionDataDelegate" fullword
    $s1545 = "otherButtonTitles" fullword
    $s1551 = "lockScreenAuthenticationDidFailWithAttempt" fullword
    $s1552 = "SSS10FoundationE19" fullword
    $s1555 = "getTupleTypeMetadata2" fullword
    $s1556 = "RGp0SARARARARARA" fullword
    $s1579 = "InitializeDistributedNotification" fullword
    $s1585 = "setAuthenticationPrompt" fullword
    $s1596 = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1598 = "textForMessageInDraggedView" fullword
    $s1599 = "kZBZeoAccountLoggedInNotification" fullword
    $s1602 = "terminationStatus" fullword
    $s1621 = "NSLayoutConstraint" fullword
    $s1622 = "didFailToRegisterForRemoteNotificationsWithError" fullword
    $s1633 = "NSJSONSerialization" fullword
    $s1635 = "didDismissWithButtonIndex" fullword
    $s1646 = "shouldChangeCharactersInRange" fullword
    $s1647 = "CSo12NSDictionary" fullword
    $s1648 = "autoreleasePoolPushv" fullword
    $s1658 = "JSValueMakeBoolean" fullword
    $s1686 = "496e666f2e706c697374" fullword
    $s1691 = "setAttributedTitle" fullword
    $s1698 = "systemVersionString" fullword
    $s1701 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1715 = "shouldDragDocumentWithEvent" fullword
    $s1730 = "getInjectedParams" fullword
    $s1733 = "readDataOfLength" fullword
    $s1751 = "UHAWAVAUATSPIIIMthMtcL" fullword
    $s1759 = "isExecutableFileAtPath" fullword
    $s1780 = "redirectResponse" fullword
    $s1781 = "SecStaticCodeCheckValidityWithErrors" fullword
    $s1796 = "initWithSuiteName" fullword
    $s1819 = "initWithFireDate" fullword
    $s1820 = "runningApplicationWithProcessIdentifier" fullword
    $s1821 = "setWebViewController" fullword
    $s1823 = "clientSocketWithRequest" fullword
    $s1824 = "IORegistryEntryCreateCFProperty" fullword
    $s1826 = "NSUserNotificationCenterDelegate" fullword
    $s1827 = "showNotification" fullword
    $s1828 = "dataTaskWithRequest" fullword
    $s1837 = "ZL19transcribeProtocolsP10objc" fullword
    $s1841 = "shouldSaveApplicationState" fullword
    $s1845 = "whatIsPluginDescription" fullword
    $s1880 = "NSDistributedNotificationCenter" fullword
    $s1888 = "copyClassNamesForImage" fullword
    $s1891 = "decodeObjectOfClasses" fullword
    $s1899 = "connectionRequired" fullword
    $s1906 = "isPathOnExternalDevice" fullword
    $s1907 = "connectGestureRecognized" fullword
    $s1915 = "Dfllononqpqpsrr2" fullword
    $s1921 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1931 = "kSecMatchLimitAll" fullword
    $s1955 = "ZBTypeCategoryNames" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 1.5)
        and ((#s2 <= 1.5)
          and ((#s3 <= 0.5)
            and ((#s4 <= 5.5)
              and ((#s5 <= 0.5)
                and ((#s6 <= 0.5)
                  and ((#s7 <= 1.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 1.0)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 1.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 0.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 0.5)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 0.5)
                                                        and ((#s26 <= 2.0)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 1.0)
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 0.5)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 2.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 1.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((#s36 <= 1.0)
                                                                              and ((#s37 <= 0.5)
                                                                                and ((#s38 <= 0.5)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 0.5)
                                                                                                    and ((#s48 <= 1.5)
                                                                                                      and ((filesize <= 50006.0)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 1.5)
                                                                                                            and ((#s4 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                      and ((#s57 <= 1.0)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 1.0)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 1.0)
                                                                                                                                                          and ((#s75 <= 0.5)
                                                                                                                                                            and ((#s76 <= 0.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                                      and ((filesize <= 16436.0)
                                                                                                                                                                        and ((#s82 <= 0.5)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((#s84 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                and ((#s86 <= 1.5)
                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                      and ((#s89 <= 0.5)
                                                                                                                                                                                        and ((#s90 <= 1.0)
                                                                                                                                                                                          and ((filesize > 4222.0)
                                                                                                                                                                                            and ((#s93 <= 0.5)
                                                                                                                                                                                              and ((#s94 <= 0.5)
                                                                                                                                                                                                and ((filesize <= 5196.0)
                                                                                                                                                                                                  and ((filesize > 5176.0)
                                                                                                                                                                                                  ) or (filesize > 5196.0)
                                                                                                                                                                                                  and ((#s101 <= 0.5)
                                                                                                                                                                                                    and ((filesize > 12526.0)
                                                                                                                                                                                                      and ((filesize <= 12546.0)
                                                                                                                                                                                                      )))))))))))))))) or (filesize > 16436.0)
                                                                                                                                                                        and ((#s119 <= 0.5)
                                                                                                                                                                          and ((#s120 <= 0.5)
                                                                                                                                                                            and ((#s121 <= 0.5)
                                                                                                                                                                              and ((#s122 <= 1.0)
                                                                                                                                                                                and ((#s123 <= 0.5)
                                                                                                                                                                                  and ((filesize <= 16478.0)
                                                                                                                                                                                    or (filesize > 16478.0)
                                                                                                                                                                                    and ((#s126 <= 0.5)
                                                                                                                                                                                      and ((#s127 <= 1.0)
                                                                                                                                                                                        and ((#s128 <= 0.5)
                                                                                                                                                                                          and ((#s51 <= 0.5)
                                                                                                                                                                                            and ((#s130 <= 0.5)
                                                                                                                                                                                              and ((#s131 <= 0.5)
                                                                                                                                                                                                and ((#s132 <= 1.0)
                                                                                                                                                                                                  and ((#s85 <= 0.5)
                                                                                                                                                                                                    and ((#s93 <= 0.5)
                                                                                                                                                                                                      and ((#s89 <= 0.5)
                                                                                                                                                                                                        and ((#s136 <= 0.5)
                                                                                                                                                                                                          and ((#s137 <= 3.0)
                                                                                                                                                                                                            and ((#s86 <= 0.5)
                                                                                                                                                                                                              and ((#s94 <= 0.5)
                                                                                                                                                                                                                and ((#s140 <= 0.5)
                                                                                                                                                                                                                  and ((#s88 <= 0.5)
                                                                                                                                                                                                                    and ((#s83 <= 0.5)
                                                                                                                                                                                                                      and ((#s143 <= 0.5)
                                                                                                                                                                                                                        and ((#s87 <= 1.0)
                                                                                                                                                                                                                          and ((#s145 <= 0.5)
                                                                                                                                                                                                                            and ((filesize <= 26130.0)
                                                                                                                                                                                                                              and ((#s147 <= 0.5)
                                                                                                                                                                                                                                and ((filesize <= 26056.0)
                                                                                                                                                                                                                                  and ((#s149 <= 1.0)
                                                                                                                                                                                                                                    and ((#s150 <= 1.0)
                                                                                                                                                                                                                                      and ((filesize <= 20788.0)
                                                                                                                                                                                                                                        and ((filesize > 18982.0)
                                                                                                                                                                                                                                          and ((filesize <= 19022.0)
                                                                                                                                                                                                                                          )) or (filesize > 20788.0)
                                                                                                                                                                                                                                        and ((filesize <= 20802.0)
                                                                                                                                                                                                                                          or (filesize > 20802.0)
                                                                                                                                                                                                                                          and ((filesize <= 21056.0)
                                                                                                                                                                                                                                            and ((filesize > 21000.0)
                                                                                                                                                                                                                                            ) or (filesize > 21056.0)
                                                                                                                                                                                                                                            and ((filesize > 25136.0)
                                                                                                                                                                                                                                              and ((filesize <= 25188.0)
                                                                                                                                                                                                                                              ))))))) or (filesize > 26056.0)
                                                                                                                                                                                                                                ) or (#s147 > 0.5)
                                                                                                                                                                                                                              ) or (filesize > 26130.0)
                                                                                                                                                                                                                              and ((#s84 <= 0.5)
                                                                                                                                                                                                                                and ((#s173 <= 0.5)
                                                                                                                                                                                                                                  and ((#s174 <= 0.5)
                                                                                                                                                                                                                                    and ((#s175 <= 3.0)
                                                                                                                                                                                                                                      and ((#s176 <= 1.0)
                                                                                                                                                                                                                                        and ((#s149 <= 1.0)
                                                                                                                                                                                                                                          and ((#s178 > 0.5)
                                                                                                                                                                                                                                          )))))))))) or (#s143 > 0.5)
                                                                                                                                                                                                                      )))))) or (#s137 > 3.0)
                                                                                                                                                                                                          ))))))) or (#s130 > 0.5)
                                                                                                                                                                                              and ((filesize <= 28162.0)
                                                                                                                                                                                              ))))))))))))))) or (#s78 > 0.5)
                                                                                                                                                                ))))) or (#s73 > 0.5)
                                                                                                                                                      ))) or (#s70 > 0.5)
                                                                                                                                                )))) or (#s66 > 0.5)
                                                                                                                                        )))))) or (#s60 > 0.5)
                                                                                                                            ))) or (#s57 > 1.0)
                                                                                                                      )) or (#s55 > 0.5)
                                                                                                                    and ((#s126 <= 0.5)
                                                                                                                      and ((filesize > 27302.0)
                                                                                                                      ))) or (#s54 > 0.5)
                                                                                                                )) or (#s4 > 0.5)
                                                                                                              and ((#s68 <= 1.0)
                                                                                                              )) or (#s51 > 1.5)
                                                                                                            and ((#s253 <= 1.0)
                                                                                                              and ((#s254 <= 1.0)
                                                                                                                and ((#s88 <= 1.0)
                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                    and ((#s126 <= 0.5)
                                                                                                                    ))))))) or (filesize > 50006.0)
                                                                                                        and ((#s265 <= 0.5)
                                                                                                          and ((filesize <= 50212.0)
                                                                                                            and ((#s267 <= 0.5)
                                                                                                              and ((#s268 <= 0.5)
                                                                                                                and ((#s269 <= 0.5)
                                                                                                                  and ((filesize <= 50114.0)
                                                                                                                    and ((filesize <= 50062.0)
                                                                                                                    ) or (filesize > 50114.0)
                                                                                                                  ) or (#s269 > 0.5)
                                                                                                                ) or (#s268 > 0.5)
                                                                                                              )) or (filesize > 50212.0)
                                                                                                            and ((#s85 <= 0.5)
                                                                                                              and ((filesize <= 457316.0)
                                                                                                                and ((#s280 <= 0.5)
                                                                                                                  and ((#s281 <= 0.5)
                                                                                                                    and ((#s282 <= 0.5)
                                                                                                                      and ((#s75 <= 0.5)
                                                                                                                        and ((#s149 <= 0.5)
                                                                                                                          and ((#s131 <= 0.5)
                                                                                                                            and ((#s286 <= 0.5)
                                                                                                                              and ((#s48 <= 0.5)
                                                                                                                                and ((#s50 <= 0.5)
                                                                                                                                  and ((#s59 <= 0.5)
                                                                                                                                    and ((#s290 <= 0.5)
                                                                                                                                      and ((#s291 <= 0.5)
                                                                                                                                        and ((#s83 <= 0.5)
                                                                                                                                          and ((filesize <= 173168.0)
                                                                                                                                            and ((#s294 <= 0.5)
                                                                                                                                              and ((#s295 <= 0.5)
                                                                                                                                                and ((#s61 <= 0.5)
                                                                                                                                                  and ((#s65 <= 0.5)
                                                                                                                                                    and ((#s298 <= 0.5)
                                                                                                                                                      and ((#s299 <= 0.5)
                                                                                                                                                        and ((#s300 <= 0.5)
                                                                                                                                                          and ((#s301 <= 0.5)
                                                                                                                                                            and ((#s302 <= 1.0)
                                                                                                                                                              and ((#s303 <= 0.5)
                                                                                                                                                                and ((#s304 <= 0.5)
                                                                                                                                                                  and ((#s87 <= 1.0)
                                                                                                                                                                    and ((#s150 <= 1.0)
                                                                                                                                                                      and ((#s130 <= 0.5)
                                                                                                                                                                        and ((#s308 <= 0.5)
                                                                                                                                                                          and ((#s55 <= 19.0)
                                                                                                                                                                            and ((#s51 <= 0.5)
                                                                                                                                                                              and ((#s86 <= 11.0)
                                                                                                                                                                                and ((#s253 <= 0.5)
                                                                                                                                                                                  and ((#s136 <= 0.5)
                                                                                                                                                                                    and ((#s314 <= 1.0)
                                                                                                                                                                                      and ((#s4 <= 0.5)
                                                                                                                                                                                        and ((#s67 <= 1.0)
                                                                                                                                                                                          and ((#s317 <= 1.0)
                                                                                                                                                                                            and ((#s318 <= 1.0)
                                                                                                                                                                                              and ((#s319 <= 0.5)
                                                                                                                                                                                                and ((#s320 <= 0.5)
                                                                                                                                                                                                  and ((#s321 <= 0.5)
                                                                                                                                                                                                    and ((#s322 <= 0.5)
                                                                                                                                                                                                      and ((#s323 <= 0.5)
                                                                                                                                                                                                        and ((#s79 <= 1.0)
                                                                                                                                                                                                          and ((#s88 <= 0.5)
                                                                                                                                                                                                            and ((#s326 <= 1.0)
                                                                                                                                                                                                              and ((#s327 <= 1.0)
                                                                                                                                                                                                                and ((#s84 <= 1.0)
                                                                                                                                                                                                                  and ((#s329 <= 0.5)
                                                                                                                                                                                                                    and ((#s330 <= 0.5)
                                                                                                                                                                                                                      and ((#s331 <= 1.0)
                                                                                                                                                                                                                        and ((#s332 <= 0.5)
                                                                                                                                                                                                                          and ((#s333 <= 0.5)
                                                                                                                                                                                                                            and ((filesize <= 100238.0)
                                                                                                                                                                                                                              and ((filesize <= 99224.0)
                                                                                                                                                                                                                                and ((filesize > 71036.0)
                                                                                                                                                                                                                                  and ((filesize <= 71180.0)
                                                                                                                                                                                                                                    or (filesize > 71180.0)
                                                                                                                                                                                                                                    and ((filesize <= 71394.0)
                                                                                                                                                                                                                                      and ((filesize > 71220.0)
                                                                                                                                                                                                                                      ) or (filesize > 71394.0)
                                                                                                                                                                                                                                      and ((filesize <= 79752.0)
                                                                                                                                                                                                                                        and ((filesize > 79716.0)
                                                                                                                                                                                                                                        ))))) or (filesize > 99224.0)
                                                                                                                                                                                                                              )))))))))))))))))))))))))))))))))))))))))) or (filesize > 173168.0)
                                                                                                                                            and ((#s332 <= 0.5)
                                                                                                                                              and ((#s55 <= 0.5)
                                                                                                                                                and ((#s393 <= 0.5)
                                                                                                                                                  and ((#s394 <= 0.5)
                                                                                                                                                    and ((#s330 <= 0.5)
                                                                                                                                                      and ((#s323 <= 0.5)
                                                                                                                                                        and ((#s318 <= 0.5)
                                                                                                                                                          and ((#s398 <= 0.5)
                                                                                                                                                            and ((#s128 <= 0.5)
                                                                                                                                                              and ((#s119 <= 1.0)
                                                                                                                                                                and ((#s304 <= 0.5)
                                                                                                                                                                  and ((#s402 <= 0.5)
                                                                                                                                                                    and ((#s51 <= 0.5)
                                                                                                                                                                      and ((#s121 <= 0.5)
                                                                                                                                                                        and ((#s321 <= 0.5)
                                                                                                                                                                          and ((#s79 <= 1.0)
                                                                                                                                                                            and ((#s407 <= 1.5)
                                                                                                                                                                              and ((#s314 <= 1.0)
                                                                                                                                                                                and ((#s136 <= 0.5)
                                                                                                                                                                                  and ((#s150 <= 1.0)
                                                                                                                                                                                    and ((#s88 <= 1.5)
                                                                                                                                                                                      and ((#s299 <= 0.5)
                                                                                                                                                                                        and ((filesize <= 174340.0)
                                                                                                                                                                                          or (filesize > 174340.0)
                                                                                                                                                                                          and ((#s415 <= 0.5)
                                                                                                                                                                                            and ((#s130 <= 0.5)
                                                                                                                                                                                              and ((filesize > 409912.0)
                                                                                                                                                                                                and ((filesize <= 424206.0)
                                                                                                                                                                                                ))))))))))))))))))))))))))))))))) or (#s48 > 0.5)
                                                                                                                                and ((#s451 > 0.5)
                                                                                                                                ))))))))) or (filesize > 457316.0)
                                                                                                                and ((#s281 <= 0.5)
                                                                                                                  and ((#s150 <= 0.5)
                                                                                                                    and ((#s75 <= 0.5)
                                                                                                                      and ((#s464 <= 0.5)
                                                                                                                        and ((#s465 <= 0.5)
                                                                                                                          and ((#s466 <= 3.0)
                                                                                                                            and ((#s136 <= 0.5)
                                                                                                                              and ((#s62 <= 0.5)
                                                                                                                                and ((#s469 <= 0.5)
                                                                                                                                  and ((#s323 <= 0.5)
                                                                                                                                    and ((#s83 <= 0.5)
                                                                                                                                      and ((#s472 <= 0.5)
                                                                                                                                        and ((#s473 <= 1.0)
                                                                                                                                          and ((#s119 <= 0.5)
                                                                                                                                            and ((#s4 <= 0.5)
                                                                                                                                              and ((#s476 <= 0.5)
                                                                                                                                                and ((#s477 <= 0.5)
                                                                                                                                                  and ((#s407 <= 0.5)
                                                                                                                                                    and ((#s130 <= 0.5)
                                                                                                                                                      and ((#s60 <= 0.5)
                                                                                                                                                        and ((#s128 <= 0.5)
                                                                                                                                                          and ((#s51 <= 0.5)
                                                                                                                                                            and ((#s68 <= 4.0)
                                                                                                                                                              and ((#s484 <= 1.0)
                                                                                                                                                                and ((#s88 <= 0.5)
                                                                                                                                                                  and ((#s486 <= 0.5)
                                                                                                                                                                    and ((#s174 <= 3.5)
                                                                                                                                                                      and ((#s299 <= 1.0)
                                                                                                                                                                        and ((#s55 <= 2.5)
                                                                                                                                                                          and ((#s55 <= 1.5)
                                                                                                                                                                            and ((#s50 <= 0.5)
                                                                                                                                                                              and ((#s492 <= 0.5)
                                                                                                                                                                                and ((#s330 <= 0.5)
                                                                                                                                                                                  and ((#s121 <= 0.5)
                                                                                                                                                                                    and ((filesize <= 467238.0)
                                                                                                                                                                                      or (filesize > 467238.0)
                                                                                                                                                                                      and ((#s53 <= 0.5)
                                                                                                                                                                                        and ((#s498 <= 0.5)
                                                                                                                                                                                          and ((#s499 <= 1.0)
                                                                                                                                                                                            and ((#s84 <= 1.0)
                                                                                                                                                                                              and ((#s321 <= 0.5)
                                                                                                                                                                                                and ((#s55 <= 0.5)
                                                                                                                                                                                                  and ((#s82 <= 1.5)
                                                                                                                                                                                                    and ((#s149 <= 1.5)
                                                                                                                                                                                                      and ((#s505 <= 0.5)
                                                                                                                                                                                                        and ((#s506 <= 0.5)
                                                                                                                                                                                                          and ((filesize <= 624454.0)
                                                                                                                                                                                                            and ((filesize > 615196.0)
                                                                                                                                                                                                            ) or (filesize > 624454.0)
                                                                                                                                                                                                            and ((filesize > 1654735.5)
                                                                                                                                                                                                              and ((filesize <= 1763827.5)
                                                                                                                                                                                                              )))))))))) or (#s499 > 1.0)
                                                                                                                                                                                          )))))))) or (#s55 > 1.5)
                                                                                                                                                                            and ((filesize <= 523753.5)
                                                                                                                                                                            )))))))))))) or (#s130 > 0.5)
                                                                                                                                                    ))))))))))))) or (#s466 > 3.0)
                                                                                                                          ))))))))))) or (#s48 > 1.5)
                                                                                                      and ((#s564 <= 0.5)
                                                                                                        and ((#s565 <= 0.5)
                                                                                                          and ((#s566 <= 0.5)
                                                                                                            and ((#s93 <= 0.5)
                                                                                                              and ((#s568 <= 0.5)
                                                                                                                and ((#s55 <= 1.5)
                                                                                                                  and ((#s332 <= 0.5)
                                                                                                                    and ((#s83 <= 0.5)
                                                                                                                      and ((#s572 <= 1.0)
                                                                                                                        and ((#s573 <= 0.5)
                                                                                                                          and ((#s64 <= 1.0)
                                                                                                                            and ((#s51 <= 0.5)
                                                                                                                              and ((#s330 <= 0.5)
                                                                                                                                and ((#s323 <= 0.5)
                                                                                                                                  and ((filesize <= 19830.0)
                                                                                                                                    and ((#s579 <= 1.0)
                                                                                                                                      and ((#s79 <= 1.0)
                                                                                                                                        and ((#s80 <= 0.5)
                                                                                                                                          and ((#s132 <= 1.0)
                                                                                                                                            and ((filesize > 17996.0)
                                                                                                                                            ))))) or (filesize > 19830.0)
                                                                                                                                    and ((#s88 <= 1.0)
                                                                                                                                      and ((filesize > 538374.0)
                                                                                                                                        and ((#s321 <= 0.5)
                                                                                                                                          and ((#s79 <= 0.5)
                                                                                                                                            and ((#s55 <= 0.5)
                                                                                                                                              and ((filesize <= 628246.0)
                                                                                                                                              )))))))))))) or (#s572 > 1.0)
                                                                                                                        and ((#s321 <= 0.5)
                                                                                                                          and ((#s609 <= 0.5)
                                                                                                                            and ((#s610 <= 1.0)
                                                                                                                              and ((#s611 <= 0.5)
                                                                                                                                and ((filesize <= 13724.0)
                                                                                                                                  and ((#s613 <= 1.0)
                                                                                                                                    and ((#s64 > 1.0)
                                                                                                                                      and ((filesize > 8318.0)
                                                                                                                                      ))) or (filesize > 13724.0)
                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                    and ((#s625 <= 0.5)
                                                                                                                                      and ((filesize <= 46364.0)
                                                                                                                                        and ((#s64 > 1.0)
                                                                                                                                          and ((#s613 <= 1.0)
                                                                                                                                            or (#s613 > 1.0)
                                                                                                                                            and ((filesize <= 16072.0)
                                                                                                                                              or (filesize > 16072.0)
                                                                                                                                              and ((filesize > 18120.0)
                                                                                                                                              )))) or (filesize > 46364.0)
                                                                                                                                        and ((filesize > 80228.0)
                                                                                                                                          and ((#s613 > 1.0)
                                                                                                                                          ))) or (#s625 > 0.5)
                                                                                                                                    ) or (#s79 > 0.5)
                                                                                                                                  )))) or (#s609 > 0.5)
                                                                                                                          ))))) or (#s55 > 1.5)
                                                                                                                  and ((#s572 > 1.0)
                                                                                                                  )))))) or (#s564 > 0.5)
                                                                                                      )) or (#s47 > 0.5)
                                                                                                  )) or (#s45 > 0.5)
                                                                                                and ((#s661 <= 0.5)
                                                                                                  and ((#s128 <= 0.5)
                                                                                                    and ((#s131 <= 1.0)
                                                                                                      and ((#s80 <= 0.5)
                                                                                                        and ((#s407 <= 0.5)
                                                                                                          and ((#s136 <= 0.5)
                                                                                                            and ((#s667 <= 1.0)
                                                                                                              and ((#s122 <= 1.0)
                                                                                                                and ((#s121 <= 0.5)
                                                                                                                  and ((#s329 <= 0.5)
                                                                                                                    and ((#s671 <= 0.5)
                                                                                                                      and ((#s672 <= 1.5)
                                                                                                                        and ((#s673 <= 1.0)
                                                                                                                          and ((#s674 <= 1.0)
                                                                                                                            and ((filesize <= 31638.0)
                                                                                                                            )))))))))))))))) or (#s44 > 0.5)
                                                                                              and ((#s692 <= 0.5)
                                                                                                and ((filesize <= 9040853.5)
                                                                                                  and ((#s465 > 0.5)
                                                                                                  ) or (filesize > 9040853.5)
                                                                                                ))) or (#s43 > 0.5)
                                                                                          ) or (#s42 > 0.5)
                                                                                          and ((#s700 <= 1.5)
                                                                                            and ((#s701 <= 0.5)
                                                                                              and ((#s59 <= 0.5)
                                                                                                and ((#s465 > 1.5)
                                                                                                  and ((#s72 <= 0.5)
                                                                                                  ))) or (#s701 > 0.5)
                                                                                            )))) or (#s40 > 0.5)
                                                                                      and ((#s83 <= 1.5)
                                                                                        and ((#s50 <= 0.5)
                                                                                          and ((#s714 <= 0.5)
                                                                                            and ((#s123 <= 0.5)
                                                                                              and ((#s716 <= 1.5)
                                                                                                and ((#s717 <= 0.5)
                                                                                                  and ((#s718 <= 0.5)
                                                                                                    and ((#s126 <= 0.5)
                                                                                                      and ((#s121 <= 0.5)
                                                                                                        and ((#s451 <= 0.5)
                                                                                                          and ((#s333 <= 0.5)
                                                                                                            and ((#s723 <= 0.5)
                                                                                                              and ((#s724 <= 0.5)
                                                                                                                and ((#s132 <= 1.0)
                                                                                                                  and ((#s301 <= 0.5)
                                                                                                                    and ((#s498 <= 0.5)
                                                                                                                      and ((#s728 <= 0.5)
                                                                                                                        and ((#s729 <= 0.5)
                                                                                                                          and ((#s661 > 1.0)
                                                                                                                          )) or (#s728 > 0.5)
                                                                                                                      )))))))) or (#s121 > 0.5)
                                                                                                        and ((#s742 <= 1.0)
                                                                                                          and ((#s743 <= 0.5)
                                                                                                            and ((#s398 <= 0.5)
                                                                                                              and ((#s80 > 0.5)
                                                                                                                and ((filesize <= 89154.0)
                                                                                                                ))) or (#s743 > 0.5)
                                                                                                          )))))) or (#s716 > 1.5)
                                                                                              )))) or (#s83 > 1.5)
                                                                                        and ((#s94 <= 1.0)
                                                                                          and ((#s323 <= 0.5)
                                                                                            and ((#s762 <= 1.0)
                                                                                              and ((#s763 <= 1.0)
                                                                                                and ((#s723 <= 1.0)
                                                                                                  and ((#s42 <= 3.0)
                                                                                                    and ((#s72 <= 0.5)
                                                                                                      and ((#s76 <= 1.0)
                                                                                                        and ((#s282 <= 0.5)
                                                                                                          and ((#s121 > 1.0)
                                                                                                            and ((#s295 > 1.0)
                                                                                                            ))))) or (#s42 > 3.0)
                                                                                                    and ((#s466 > 1.0)
                                                                                                    ))) or (#s763 > 1.0)
                                                                                                and ((filesize <= 60748.0)
                                                                                                  and ((#s398 > 0.5)
                                                                                                  ))) or (#s762 > 1.0)
                                                                                            ))))) or (#s39 > 0.5)
                                                                                    and ((#s136 <= 0.5)
                                                                                      and ((#s42 <= 1.0)
                                                                                        and ((#s321 <= 0.5)
                                                                                          and ((#s281 <= 0.5)
                                                                                            and ((#s68 <= 1.0)
                                                                                              and ((#s85 <= 0.5)
                                                                                                and ((#s51 <= 1.0)
                                                                                                  and ((#s76 <= 1.0)
                                                                                                    and ((#s39 > 1.5)
                                                                                                      and ((#s119 <= 1.0)
                                                                                                        and ((#s318 <= 1.0)
                                                                                                          and ((#s87 > 1.0)
                                                                                                            and ((#s803 > 1.0)
                                                                                                              and ((#s127 <= 1.0)
                                                                                                                and ((#s330 <= 0.5)
                                                                                                                  and ((#s40 > 1.0)
                                                                                                                    and ((#s323 > 0.5)
                                                                                                                    )))))))))))))))))) or (#s38 > 0.5)
                                                                                ) or (#s37 > 0.5)
                                                                              ) or (#s36 > 1.0)
                                                                            ) or (#s35 > 0.5)
                                                                          ) or (#s34 > 1.5)
                                                                          and ((#s329 <= 3.0)
                                                                            and ((#s829 <= 0.5)
                                                                              and ((#s742 <= 1.0)
                                                                                and ((#s39 <= 1.0)
                                                                                  and ((#s832 <= 2.0)
                                                                                    and ((#s724 <= 0.5)
                                                                                      and ((#s834 <= 30.0)
                                                                                        and ((#s835 <= 0.5)
                                                                                          and ((#s836 <= 1.0)
                                                                                            and ((#s131 > 1.0)
                                                                                              and ((#s323 <= 2.0)
                                                                                                and ((#s150 > 1.0)
                                                                                                )))) or (#s835 > 0.5)
                                                                                        )))))) or (#s829 > 0.5)
                                                                            ) or (#s329 > 3.0)
                                                                          )) or (#s33 > 0.5)
                                                                        and ((#s853 <= 1.0)
                                                                          and ((#s854 <= 0.5)
                                                                            and ((#s855 <= 0.5)
                                                                              and ((#s856 <= 0.5)
                                                                                and ((#s857 <= 2.0)
                                                                                  and ((#s858 <= 0.5)
                                                                                    and ((#s859 <= 1.0)
                                                                                      and ((#s860 <= 0.5)
                                                                                        and ((#s93 <= 0.5)
                                                                                          and ((filesize <= 33936.0)
                                                                                            and ((#s863 <= 0.5)
                                                                                              and ((#s76 <= 0.5)
                                                                                                and ((#s865 <= 1.0)
                                                                                                  and ((#s72 <= 0.5)
                                                                                                    and ((#s75 <= 1.0)
                                                                                                      and ((#s868 <= 0.5)
                                                                                                        and ((#s63 <= 0.5)
                                                                                                          and ((#s870 <= 0.5)
                                                                                                            and ((#s871 <= 0.5)
                                                                                                              and ((#s872 <= 1.0)
                                                                                                                and ((#s51 <= 1.0)
                                                                                                                  and ((#s874 <= 0.5)
                                                                                                                    and ((#s45 <= 0.5)
                                                                                                                      and ((#s121 <= 1.0)
                                                                                                                        and ((#s877 <= 0.5)
                                                                                                                          and ((#s565 <= 0.5)
                                                                                                                            and ((#s88 <= 1.0)
                                                                                                                              and ((#s41 <= 1.0)
                                                                                                                                and ((#s71 <= 0.5)
                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                    and ((#s883 <= 0.5)
                                                                                                                                      and ((#s884 <= 0.5)
                                                                                                                                        and ((#s885 > 0.5)
                                                                                                                                          and ((#s132 <= 1.0)
                                                                                                                                            and ((#s888 <= 0.5)
                                                                                                                                              and ((#s40 <= 1.0)
                                                                                                                                                and ((#s33 <= 1.5)
                                                                                                                                                  and ((filesize <= 16816.0)
                                                                                                                                                    and ((filesize > 14880.0)
                                                                                                                                                    )) or (#s33 > 1.5)
                                                                                                                                                  and ((#s300 <= 0.5)
                                                                                                                                                    and ((#s84 <= 1.0)
                                                                                                                                                      and ((#s42 <= 1.0)
                                                                                                                                                        and ((#s83 <= 0.5)
                                                                                                                                                          and ((#s48 <= 1.0)
                                                                                                                                                            and ((#s50 <= 1.0)
                                                                                                                                                              and ((#s333 <= 1.0)
                                                                                                                                                                and ((#s903 <= 0.5)
                                                                                                                                                                  and ((filesize <= 23992.0)
                                                                                                                                                                    and ((filesize <= 23824.0)
                                                                                                                                                                      and ((filesize > 18896.0)
                                                                                                                                                                        and ((filesize <= 19280.0)
                                                                                                                                                                        )) or (filesize > 23824.0)
                                                                                                                                                                    )))) or (#s50 > 1.0)
                                                                                                                                                            )))))))) or (#s888 > 0.5)
                                                                                                                                              and ((filesize <= 27528.0)
                                                                                                                                              )))) or (#s884 > 0.5)
                                                                                                                                      )))) or (#s41 > 1.0)
                                                                                                                              ))))) or (#s45 > 0.5)
                                                                                                                    ))) or (#s872 > 1.0)
                                                                                                                and ((#s333 <= 2.5)
                                                                                                                  or (#s333 > 2.5)
                                                                                                                  and ((filesize <= 17096.0)
                                                                                                                  )))) or (#s870 > 0.5)
                                                                                                          )) or (#s868 > 0.5)
                                                                                                      )) or (#s72 > 0.5)
                                                                                                    and ((#s42 > 1.0)
                                                                                                    ))))) or (filesize > 33936.0)
                                                                                            and ((#s295 <= 0.5)
                                                                                              and ((#s955 <= 0.5)
                                                                                                and ((#s83 <= 1.5)
                                                                                                  and ((#s299 <= 1.0)
                                                                                                    and ((#s958 <= 1.0)
                                                                                                      and ((#s888 <= 0.5)
                                                                                                        and ((#s53 <= 0.5)
                                                                                                          and ((#s280 <= 0.5)
                                                                                                            and ((#s402 <= 0.5)
                                                                                                              and ((#s963 <= 0.5)
                                                                                                                and ((#s130 <= 0.5)
                                                                                                                  and ((#s39 <= 0.5)
                                                                                                                    and ((#s883 <= 0.5)
                                                                                                                      and ((#s967 <= 1.0)
                                                                                                                        and ((#s76 <= 0.5)
                                                                                                                          and ((#s407 <= 0.5)
                                                                                                                            and ((#s55 <= 0.5)
                                                                                                                              and ((#s75 <= 1.0)
                                                                                                                                and ((#s132 <= 1.0)
                                                                                                                                  and ((#s131 <= 1.0)
                                                                                                                                    and ((#s84 <= 1.0)
                                                                                                                                      and ((#s975 <= 1.0)
                                                                                                                                        and ((#s68 <= 0.5)
                                                                                                                                          and ((#s42 <= 1.0)
                                                                                                                                            and ((#s80 <= 1.5)
                                                                                                                                              and ((#s979 <= 0.5)
                                                                                                                                                and ((#s885 > 0.5)
                                                                                                                                                  and ((#s982 <= 13.5)
                                                                                                                                                    and ((#s136 <= 0.5)
                                                                                                                                                      and ((#s836 <= 1.0)
                                                                                                                                                        and ((#s79 <= 0.5)
                                                                                                                                                          and ((#s986 <= 7.0)
                                                                                                                                                            and ((#s40 <= 0.5)
                                                                                                                                                              and ((#s671 <= 0.5)
                                                                                                                                                                and ((#s320 <= 1.0)
                                                                                                                                                                  and ((#s505 <= 0.5)
                                                                                                                                                                    and ((#s300 <= 0.5)
                                                                                                                                                                      and ((#s673 <= 1.0)
                                                                                                                                                                        and ((#s323 <= 0.5)
                                                                                                                                                                          and ((#s994 <= 0.5)
                                                                                                                                                                            and ((#s175 <= 4.0)
                                                                                                                                                                              and ((#s329 <= 0.5)
                                                                                                                                                                                and ((#s48 <= 1.0)
                                                                                                                                                                                  and ((#s121 <= 1.0)
                                                                                                                                                                                    and ((#s50 <= 0.5)
                                                                                                                                                                                      and ((#s903 <= 0.5)
                                                                                                                                                                                        and ((#s34 <= 1.0)
                                                                                                                                                                                          and ((#s149 <= 1.0)
                                                                                                                                                                                            and ((#s330 <= 0.5)
                                                                                                                                                                                              and ((#s45 <= 0.5)
                                                                                                                                                                                                and ((#s1005 <= 0.5)
                                                                                                                                                                                                  and ((#s33 <= 3.0)
                                                                                                                                                                                                    and ((#s33 > 1.5)
                                                                                                                                                                                                      and ((#s150 <= 1.0)
                                                                                                                                                                                                        and ((#s321 <= 0.5)
                                                                                                                                                                                                          and ((#s318 <= 1.0)
                                                                                                                                                                                                            and ((#s333 <= 1.0)
                                                                                                                                                                                                              and ((#s1013 <= 0.5)
                                                                                                                                                                                                                and ((filesize <= 36800.0)
                                                                                                                                                                                                                  and ((filesize > 36552.0)
                                                                                                                                                                                                                  ))))))))))))))))))))))))))))))) or (#s136 > 0.5)
                                                                                                                                                      and ((#s1047 <= 0.5)
                                                                                                                                                        and ((#s1048 <= 0.5)
                                                                                                                                                          and ((filesize > 244685.5)
                                                                                                                                                          )))))))))))) or (#s131 > 1.0)
                                                                                                                                  )))))))))))))) or (#s888 > 0.5)
                                                                                                        and ((#s121 <= 0.5)
                                                                                                          and ((#s1076 > 0.5)
                                                                                                          ))))) or (#s83 > 1.5)
                                                                                                  and ((#s90 <= 0.5)
                                                                                                    and ((#s1083 <= 0.5)
                                                                                                      and ((#s80 <= 1.0)
                                                                                                        and ((#s127 <= 1.0)
                                                                                                          and ((#s871 > 0.5)
                                                                                                            and ((#s994 <= 0.5)
                                                                                                              and ((#s1089 <= 1.0)
                                                                                                                and ((#s1090 > 0.5)
                                                                                                                )))))) or (#s1083 > 0.5)
                                                                                                      and ((#s40 <= 1.0)
                                                                                                      )))) or (#s955 > 0.5)
                                                                                                and ((#s579 <= 1.0)
                                                                                                  and ((#s1102 <= 1.0)
                                                                                                    and ((#s280 > 0.5)
                                                                                                    )))) or (#s295 > 0.5)
                                                                                              and ((#s80 <= 1.5)
                                                                                                and ((#s1109 <= 0.5)
                                                                                                  and ((#s333 <= 0.5)
                                                                                                    and ((#s1111 <= 0.5)
                                                                                                      and ((#s42 <= 1.5)
                                                                                                        and ((#s700 <= 0.5)
                                                                                                          and ((filesize > 98064.0)
                                                                                                            and ((#s1116 > 0.5)
                                                                                                            )))) or (#s1111 > 0.5)
                                                                                                      and ((#s126 <= 0.5)
                                                                                                      )))))))) or (#s860 > 0.5)
                                                                                      ) or (#s859 > 1.0)
                                                                                    ) or (#s858 > 0.5)
                                                                                    and ((#s1130 <= 0.5)
                                                                                      and ((#s1131 > 1.0)
                                                                                      ))) or (#s857 > 2.0)
                                                                                ) or (#s856 > 0.5)
                                                                                and ((#s724 <= 0.5)
                                                                                )) or (#s855 > 0.5)
                                                                            ) or (#s854 > 0.5)
                                                                            and ((#s48 <= 1.0)
                                                                              and ((#s80 <= 2.0)
                                                                                and ((#s994 > 0.5)
                                                                                )))) or (#s853 > 1.0)
                                                                        )) or (#s32 > 2.5)
                                                                      and ((#s1148 > 0.5)
                                                                      )) or (#s31 > 0.5)
                                                                  ) or (#s30 > 0.5)
                                                                  and ((#s469 <= 3.5)
                                                                    and ((#s1153 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s281 <= 1.5)
                                                                          and ((#s62 > 1.5)
                                                                            and ((#s674 > 0.5)
                                                                            )) or (#s281 > 1.5)
                                                                          and ((#s667 <= 0.5)
                                                                            and ((#s1162 <= 0.5)
                                                                              and ((#s469 <= 0.5)
                                                                                and ((#s308 <= 1.0)
                                                                                  and ((#s566 <= 1.0)
                                                                                  ))) or (#s1162 > 0.5)
                                                                            ))) or (#s33 > 0.5)
                                                                        and ((#s700 <= 0.5)
                                                                          and ((#s101 > 1.5)
                                                                            and ((#s1175 > 0.5)
                                                                            )))) or (#s1153 > 0.5)
                                                                      and ((#s174 <= 7.0)
                                                                        and ((#s1180 <= 0.5)
                                                                          and ((#s63 <= 0.5)
                                                                            and ((#s1182 <= 0.5)
                                                                              and ((#s1183 <= 2.5)
                                                                                and ((#s1184 > 0.5)
                                                                                ))) or (#s63 > 0.5)
                                                                            and ((#s476 <= 0.5)
                                                                            )) or (#s1180 > 0.5)
                                                                        ) or (#s174 > 7.0)
                                                                        and ((#s1193 > 0.5)
                                                                          and ((#s868 <= 0.5)
                                                                          )))) or (#s469 > 3.5)
                                                                    and ((#s1198 <= 0.5)
                                                                      and ((#s62 > 2.5)
                                                                        and ((#s40 <= 1.0)
                                                                          and ((#s1202 > 0.5)
                                                                            and ((#s1204 <= 2.0)
                                                                            ))))))) or (#s29 > 0.5)
                                                              ) or (#s28 > 1.0)
                                                            ) or (#s27 > 0.5)
                                                          ) or (#s26 > 2.0)
                                                        ) or (#s25 > 0.5)
                                                      ) or (#s24 > 0.5)
                                                      and ((#s1214 <= 1.5)
                                                        and ((#s1215 <= 0.5)
                                                          and ((#s885 <= 0.5)
                                                            and ((#s119 <= 1.0)
                                                              and ((#s121 <= 2.5)
                                                                and ((#s89 <= 0.5)
                                                                  and ((#s41 <= 1.0)
                                                                    and ((#s126 <= 0.5)
                                                                    ) or (#s41 > 1.0)
                                                                    and ((#s58 <= 0.5)
                                                                      and ((#s883 <= 0.5)
                                                                      ))) or (#s89 > 0.5)
                                                                  and ((#s1229 > 0.5)
                                                                    and ((#s1231 > 16.5)
                                                                    ))) or (#s121 > 2.5)
                                                                and ((#s79 > 1.5)
                                                                )) or (#s119 > 1.0)
                                                              and ((#s48 > 1.0)
                                                              )) or (#s885 > 0.5)
                                                            and ((#s863 <= 0.5)
                                                              and ((#s120 <= 0.5)
                                                                and ((#s59 <= 0.5)
                                                                  and ((#s465 <= 1.5)
                                                                    and ((#s300 <= 0.5)
                                                                      and ((filesize <= 33104.0)
                                                                      ))) or (#s59 > 0.5)
                                                                )) or (#s863 > 0.5)
                                                            )) or (#s1215 > 0.5)
                                                        ) or (#s1214 > 1.5)
                                                      )) or (#s23 > 0.5)
                                                  ) or (#s22 > 0.5)
                                                ) or (#s21 > 0.5)
                                                and ((#s1257 <= 0.5)
                                                  and ((#s1258 <= 0.5)
                                                    and ((#s1259 <= 0.5)
                                                      and ((filesize <= 92792.0)
                                                        and ((#s1261 <= 0.5)
                                                          and ((filesize <= 57452.0)
                                                            and ((#s69 <= 0.5)
                                                              and ((#s1264 <= 1.0)
                                                                and ((#s1265 <= 0.5)
                                                                  and ((#s90 > 0.5)
                                                                    and ((#s40 <= 1.0)
                                                                    )) or (#s1265 > 0.5)
                                                                  and ((#s955 <= 0.5)
                                                                    and ((#s51 <= 1.0)
                                                                      and ((#s33 > 0.5)
                                                                        and ((#s83 <= 1.0)
                                                                          or (#s83 > 1.0)
                                                                          and ((#s888 > 0.5)
                                                                          )))))))) or (filesize > 57452.0)
                                                            and ((#s1153 <= 0.5)
                                                              or (#s1153 > 0.5)
                                                              and ((#s1286 > 0.5)
                                                              ))) or (#s1261 > 0.5)
                                                          and ((#s1182 <= 1.0)
                                                            and ((#s69 <= 0.5)
                                                            ))) or (filesize > 92792.0)
                                                        and ((#s1294 <= 1.5)
                                                          and ((#s123 <= 2.5)
                                                            and ((#s1180 <= 0.5)
                                                              and ((#s1297 > 1.5)
                                                                and ((#s1299 > 13.5)
                                                                )) or (#s1180 > 0.5)
                                                              and ((#s71 <= 1.0)
                                                                and ((#s1183 <= 0.5)
                                                                  and ((#s254 <= 1.0)
                                                                    and ((#s40 <= 2.0)
                                                                      and ((#s1306 > 0.5)
                                                                      )))))) or (#s123 > 2.5)
                                                            and ((#s1313 <= 5.0)
                                                            )) or (#s1294 > 1.5)
                                                        )) or (#s1259 > 0.5)
                                                    ) or (#s1258 > 0.5)
                                                    and ((#s1318 <= 1.0)
                                                    )) or (#s1257 > 0.5)
                                                  and ((#s123 <= 0.5)
                                                    and ((#s131 <= 1.0)
                                                      and ((#s80 <= 2.5)
                                                        and ((#s51 <= 3.0)
                                                          and ((#s59 <= 0.5)
                                                            or (#s59 > 0.5)
                                                            and ((#s1327 <= 0.5)
                                                              or (#s1327 > 0.5)
                                                              and ((#s465 > 2.0)
                                                              ))) or (#s51 > 3.0)
                                                          and ((#s1299 > 28.0)
                                                          )))) or (#s123 > 0.5)
                                                    and ((#s1337 > 1.0)
                                                    )))) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                          ) or (#s18 > 0.5)
                                        ) or (#s17 > 0.5)
                                      ) or (#s16 > 1.5)
                                      and ((#s45 <= 0.5)
                                        and ((filesize <= 36104.5)
                                          and ((#s83 <= 1.0)
                                          ) or (filesize > 36104.5)
                                          and ((#s1349 <= 5.5)
                                            and ((#s1350 > 0.5)
                                              and ((#s1153 > 0.5)
                                              )) or (#s1349 > 5.5)
                                          )) or (#s45 > 0.5)
                                        and ((#s1356 > 0.5)
                                          and ((#s1358 <= 2.0)
                                          )))) or (#s15 > 0.5)
                                  ) or (#s14 > 1.0)
                                ) or (#s13 > 0.5)
                              ) or (#s12 > 0.5)
                            ) or (#s11 > 0.5)
                          ) or (#s10 > 0.5)
                          and ((#s83 <= 3.0)
                          )) or (#s9 > 0.5)
                        and ((#s1286 <= 0.5)
                          and ((#s402 <= 6.5)
                            and ((#s1371 <= 0.5)
                              and ((#s1372 <= 0.5)
                                and ((#s1373 <= 0.5)
                                  and ((#s126 > 0.5)
                                    and ((#s1376 <= 1.0)
                                      and ((#s84 <= 1.0)
                                        and ((#s568 > 0.5)
                                          and ((#s1380 <= 0.5)
                                            and ((#s128 > 0.5)
                                              and ((#s407 <= 2.5)
                                                and ((#s67 <= 0.5)
                                                  and ((#s1385 <= 1.0)
                                                  ))))))) or (#s1376 > 1.0)
                                    )) or (#s1373 > 0.5)
                                ) or (#s1372 > 0.5)
                              ) or (#s1371 > 0.5)
                            ) or (#s402 > 6.5)
                          ) or (#s1286 > 0.5)
                          and ((#s729 <= 0.5)
                            and ((#s700 > 0.5)
                              and ((#s53 <= 1.5)
                                and ((#s1401 <= 0.5)
                                  and ((#s1402 <= 0.5)
                                    and ((#s282 > 0.5)
                                    ))))) or (#s729 > 0.5)
                            and ((#s71 > 0.5)
                              and ((#s1202 <= 1.5)
                              ))))) or (#s8 > 0.5)
                    ) or (#s7 > 1.5)
                    and ((#s145 <= 2.0)
                      and ((#s994 <= 1.0)
                      ))) or (#s6 > 0.5)
                ) or (#s5 > 0.5)
                and ((#s1421 <= 1.5)
                  or (#s1421 > 1.5)
                  and ((#s320 <= 0.5)
                    or (#s320 > 0.5)
                    and ((#s87 <= 1.0)
                      and ((#s5 <= 2.5)
                        and ((#s872 <= 1.0)
                        ) or (#s5 > 2.5)
                      ) or (#s87 > 1.0)
                    )))) or (#s4 > 5.5)
              and ((#s1432 > 0.5)
                and ((#s1434 <= 1.0)
                ))) or (#s3 > 0.5)
          ) or (#s2 > 1.5)
          and ((#s83 <= 1.0)
            and ((#s888 <= 0.5)
              and ((filesize <= 985992.0)
                and ((#s1183 <= 0.5)
                  and ((#s300 <= 0.5)
                  ) or (#s1183 > 0.5)
                )) or (#s888 > 0.5)
              and ((#s1447 > 0.5)
              )) or (#s83 > 1.0)
            and ((#s136 > 2.0)
            ))) or (#s1 > 1.5)
        and ((#s858 <= 0.5)
          and ((#s1454 <= 1.0)
            and ((#s1455 <= 3.0)
              and ((#s1456 <= 0.5)
                and ((#s610 <= 0.5)
                  and ((#s69 <= 0.5)
                    and ((#s1459 <= 1.5)
                      and ((#s885 <= 0.5)
                        and ((#s121 <= 1.0)
                          and ((#s1462 <= 0.5)
                            and ((#s51 <= 0.5)
                              and ((#s1337 <= 0.5)
                                and ((#s1318 <= 0.5)
                                  and ((#s1182 > 0.5)
                                    and ((#s1380 > 0.5)
                                      and ((#s30 > 2.0)
                                        and ((#s1472 <= 0.5)
                                        ))))))) or (#s1462 > 0.5)
                          ) or (#s121 > 1.0)
                          and ((#s294 <= 1.5)
                            and ((#s1480 <= 1.5)
                              and ((#s1481 <= 1.0)
                                and ((#s128 <= 0.5)
                                  and ((#s136 <= 0.5)
                                    and ((#s176 <= 1.0)
                                      and ((#s30 <= 1.5)
                                      ) or (#s176 > 1.0)
                                    ) or (#s136 > 0.5)
                                  )))))) or (#s885 > 0.5)
                        and ((#s1494 <= 0.5)
                          and ((#s1495 <= 0.5)
                            and ((#s6 <= 0.5)
                              and ((#s1497 <= 1.5)
                                and ((#s565 <= 0.5)
                                  and ((#s1434 <= 1.0)
                                    and ((#s89 <= 1.5)
                                      and ((#s1501 <= 4.5)
                                        and ((#s1502 <= 1.5)
                                          and ((#s30 <= 2.0)
                                            and ((#s121 <= 1.0)
                                              and ((#s42 > 0.5)
                                                and ((#s280 > 2.5)
                                                  and ((#s176 <= 1.0)
                                                    and ((#s68 > 1.0)
                                                    ))))))) or (#s1501 > 4.5)
                                        and ((#s724 > 0.5)
                                          and ((#s1519 > 0.5)
                                          ))) or (#s89 > 1.5)
                                    ) or (#s1434 > 1.0)
                                  )) or (#s1497 > 1.5)
                              ) or (#s6 > 0.5)
                            ) or (#s1495 > 0.5)
                            and ((#s1313 <= 2.5)
                              and ((#s1102 <= 1.0)
                                and ((#s1529 <= 0.5)
                                  and ((#s955 <= 0.5)
                                    and ((#s1531 <= 0.5)
                                    )) or (#s1529 > 0.5)
                                  and ((#s472 <= 0.5)
                                    and ((#s955 <= 0.5)
                                      and ((#s30 > 2.0)
                                      ))))))) or (#s1494 > 0.5)
                        )) or (#s1459 > 1.5)
                      and ((#s1545 <= 0.5)
                        and ((#s1182 <= 1.5)
                          and ((#s883 <= 0.5)
                            and ((#s42 <= 2.0)
                              and ((#s88 <= 1.0)
                                and ((#s1214 <= 1.0)
                                  and ((#s1551 <= 1.5)
                                    and ((#s1552 <= 1.0)
                                      and ((#s280 <= 2.5)
                                        and ((#s83 <= 1.0)
                                          and ((#s1555 <= 1.0)
                                            and ((#s1556 <= 0.5)
                                            )))) or (#s1552 > 1.0)
                                    ) or (#s1551 > 1.5)
                                  ) or (#s1214 > 1.0)
                                  and ((#s1495 > 0.5)
                                  )))) or (#s883 > 0.5)
                            and ((#s173 <= 1.0)
                              and ((#s51 > 1.0)
                                and ((#s280 > 2.5)
                                )))) or (#s1182 > 1.5)
                          and ((#s874 <= 0.5)
                            and ((#s717 <= 0.5)
                              and ((#s1130 <= 0.5)
                                and ((#s1579 > 0.5)
                                )) or (#s717 > 0.5)
                            ) or (#s874 > 0.5)
                            and ((#s1497 <= 1.0)
                              and ((#s1585 > 1.5)
                              ) or (#s1497 > 1.0)
                            ))) or (#s1545 > 0.5)
                      )) or (#s69 > 0.5)
                    and ((#s53 <= 0.5)
                      and ((#s126 <= 1.5)
                        and ((#s1089 <= 1.0)
                          and ((#s6 <= 0.5)
                            and ((#s573 <= 0.5)
                              and ((#s863 <= 0.5)
                                and ((#s1596 <= 1.5)
                                  and ((#s565 <= 0.5)
                                    and ((#s1598 <= 0.5)
                                      and ((#s1599 <= 1.0)
                                        and ((filesize > 186032.0)
                                          and ((#s1602 > 0.5)
                                          )) or (#s1599 > 1.0)
                                      ) or (#s1598 > 0.5)
                                    ) or (#s565 > 0.5)
                                    and ((#s1258 <= 1.5)
                                      and ((#s476 <= 0.5)
                                      ))) or (#s1596 > 1.5)
                                  and ((#s295 <= 0.5)
                                    and ((#s1356 <= 0.5)
                                      and ((#s762 <= 1.0)
                                        and ((#s565 > 0.5)
                                        ) or (#s762 > 1.0)
                                      ) or (#s1356 > 0.5)
                                    ))) or (#s863 > 0.5)
                                and ((#s1621 <= 1.0)
                                  and ((#s1622 > 0.5)
                                    and ((#s1596 > 1.0)
                                    )))) or (#s573 > 0.5)
                            ) or (#s6 > 0.5)
                          )) or (#s126 > 1.5)
                      ) or (#s53 > 0.5)
                      and ((#s762 <= 1.5)
                        and ((#s1633 > 1.5)
                          and ((#s1635 <= 0.5)
                          )) or (#s762 > 1.5)
                        and ((#s1306 <= 0.5)
                          and ((#s700 > 2.5)
                          ) or (#s1306 > 0.5)
                        )))) or (#s610 > 0.5)
                  and ((#s282 <= 0.5)
                    and ((#s1596 > 1.5)
                      and ((#s1646 <= 0.5)
                        and ((#s1647 <= 1.0)
                          and ((#s1648 <= 1.0)
                            and ((#s83 > 1.0)
                              and ((filesize <= 140784.0)
                                and ((#s41 <= 1.0)
                                ))) or (#s1648 > 1.0)
                            and ((#s294 <= 1.0)
                              and ((#s1602 <= 1.5)
                                and ((#s1658 <= 1.0)
                                  and ((filesize <= 150744.0)
                                    and ((#s717 <= 0.5)
                                      and ((#s321 <= 0.5)
                                        and ((#s94 <= 1.0)
                                          and ((#s1596 <= 3.0)
                                            and ((#s466 <= 0.5)
                                              and ((#s1501 <= 5.5)
                                                or (#s1501 > 5.5)
                                                and ((#s68 <= 1.0)
                                                  and ((#s407 <= 0.5)
                                                    and ((#s1495 > 0.5)
                                                      and ((#s1214 > 1.0)
                                                      )) or (#s407 > 0.5)
                                                  ) or (#s68 > 1.0)
                                                  and ((#s41 > 2.0)
                                                  ))) or (#s466 > 0.5)
                                            ) or (#s1596 > 3.0)
                                          ))))) or (#s1658 > 1.0)
                                ) or (#s1602 > 1.5)
                              ) or (#s294 > 1.0)
                              and ((#s1686 > 0.5)
                              )))))) or (#s282 > 0.5)
                    and ((#s1691 <= 0.5)
                      and ((#s1480 > 1.5)
                        and ((#s717 <= 1.5)
                          and ((#s318 <= 1.0)
                            and ((#s321 <= 0.5)
                              and ((#s1622 <= 0.5)
                                and ((#s1698 <= 1.0)
                                  and ((#s120 <= 0.5)
                                    and ((#s1182 <= 2.0)
                                      and ((#s1701 > 1.5)
                                        and ((#s51 > 1.0)
                                          and ((#s1556 > 0.5)
                                          ))))) or (#s1698 > 1.0)
                                ) or (#s1622 > 0.5)
                                and ((#s1459 <= 1.5)
                                  and ((#s1047 > 0.5)
                                  ) or (#s1459 > 1.5)
                                  and ((#s1715 <= 0.5)
                                    and ((#s30 <= 2.0)
                                      and ((#s1481 <= 1.0)
                                      )) or (#s1715 > 0.5)
                                  )))) or (#s318 > 1.0)
                          ) or (#s717 > 1.5)
                        ))))) or (#s1456 > 0.5)
                and ((#s1090 <= 0.5)
                  and ((#s1102 <= 1.0)
                    and ((#s330 <= 0.5)
                      and ((#s1633 <= 1.0)
                        and ((#s1730 <= 1.0)
                          and ((#s300 <= 0.5)
                            and ((#s701 <= 1.0)
                              and ((#s1733 <= 0.5)
                                and ((#s89 <= 0.5)
                                  and ((#s294 <= 1.5)
                                    and ((#s1432 <= 0.5)
                                      and ((filesize > 76732.0)
                                      ) or (#s1432 > 0.5)
                                    )) or (#s89 > 0.5)
                                  and ((#s1183 > 0.5)
                                    and ((#s888 <= 0.5)
                                      and ((#s955 <= 1.5)
                                      )))) or (#s1733 > 0.5)
                              ) or (#s701 > 1.0)
                            ) or (#s300 > 0.5)
                            and ((#s1751 > 0.5)
                            )) or (#s1730 > 1.0)
                        ) or (#s1633 > 1.0)
                        and ((#s318 <= 1.0)
                          and ((#s323 <= 0.5)
                            and ((#s963 <= 0.5)
                              or (#s963 > 0.5)
                              and ((#s1759 <= 0.5)
                              )))))) or (#s1102 > 1.0)
                    and ((#s136 <= 0.5)
                      and ((#s1596 > 1.5)
                        and ((#s477 <= 1.5)
                          and ((#s1621 > 1.0)
                            and ((#s610 > 1.0)
                              and ((#s1556 > 0.5)
                                and ((#s33 > 1.0)
                                )))))) or (#s136 > 0.5)
                    )) or (#s1090 > 0.5)
                  and ((#s1780 <= 5.0)
                    and ((#s1781 <= 1.0)
                      and ((#s30 <= 2.0)
                        and ((#s863 <= 0.5)
                          and ((#s1622 > 0.5)
                          )) or (#s30 > 2.0)
                        and ((#s93 <= 0.5)
                        )))))) or (#s1455 > 3.0)
              and ((filesize <= 410624.0)
                and ((#s958 <= 2.0)
                  and ((#s1495 <= 1.5)
                    and ((#s1796 <= 1.0)
                      and ((#s1198 <= 1.0)
                        and ((#s473 <= 2.0)
                          and ((#s89 <= 0.5)
                            and ((#s1459 > 3.0)
                              and ((#s1229 <= 1.0)
                                and ((#s68 <= 2.0)
                                  and ((#s568 <= 1.0)
                                    and ((filesize <= 232856.0)
                                    ) or (#s568 > 1.0)
                                  ) or (#s68 > 2.0)
                                ))) or (#s89 > 0.5)
                          ))))))))) or (#s858 > 0.5)
          and ((#s1819 <= 0.5)
            and ((#s1820 <= 0.5)
              and ((#s1821 <= 0.5)
                and ((#s1434 <= 1.0)
                  and ((#s1823 <= 0.5)
                    and ((#s1824 <= 1.0)
                      and ((#s40 <= 1.0)
                        and ((#s1826 <= 0.5)
                          and ((#s1827 <= 0.5)
                            and ((#s1828 <= 8.5)
                              and ((#s41 <= 1.5)
                                and ((#s290 <= 10.0)
                                  and ((#s72 <= 0.5)
                                  ))) or (#s1828 > 8.5)
                              and ((#s1297 <= 1.0)
                                and ((#s1837 <= 3.0)
                                ))) or (#s1827 > 0.5)
                            and ((#s1841 > 0.5)
                            )) or (#s1826 > 0.5)
                        ) or (#s40 > 1.0)
                        and ((#s1845 <= 1.0)
                          and ((#s1401 > 0.5)
                            and ((#s667 > 0.5)
                              and ((#s80 <= 1.0)
                              ))) or (#s1845 > 1.0)
                        )) or (#s1824 > 1.0)
                      and ((filesize <= 330504.0)
                        or (filesize > 330504.0)
                        and ((#s71 <= 1.0)
                          and ((#s1495 <= 2.0)
                            and ((#s33 <= 0.5)
                              and ((#s173 <= 1.0)
                                and ((#s1313 > 10.0)
                                ))) or (#s1495 > 2.0)
                            and ((#s150 <= 1.0)
                            )) or (#s71 > 1.0)
                        ))) or (#s1823 > 0.5)
                  ) or (#s1434 > 1.0)
                ) or (#s1821 > 0.5)
                and ((#s1109 <= 1.5)
                  and ((#s1180 <= 0.5)
                    or (#s1180 > 0.5)
                    and ((#s55 <= 1.0)
                    )))) or (#s1820 > 0.5)
              and ((#s1796 <= 0.5)
                and ((#s280 <= 6.0)
                  and ((#s1880 > 1.0)
                    and ((#s402 <= 0.5)
                      and ((#s1313 <= 3.5)
                      ))) or (#s280 > 6.0)
                ) or (#s1796 > 0.5)
                and ((#s1888 > 4.0)
                ))) or (#s1819 > 0.5)
            and ((#s1891 <= 0.5)
              and ((#s294 <= 10.5)
                and ((#s717 <= 1.5)
                  and ((#s1109 <= 0.5)
                    and ((#s566 <= 1.0)
                      and ((#s119 <= 3.0)
                        or (#s119 > 3.0)
                        and ((filesize <= 18072208.0)
                          and ((#s1899 <= 1.5)
                            and ((#s299 <= 87.0)
                            ) or (#s1899 > 1.5)
                          ))) or (#s566 > 1.0)
                      and ((#s888 <= 0.5)
                        and ((#s1906 <= 1.0)
                          and ((#s1907 > 0.5)
                            and ((#s101 <= 2.5)
                              and ((#s625 <= 2.5)
                                and ((#s611 <= 0.5)
                                ) or (#s625 > 2.5)
                              ) or (#s101 > 2.5)
                              and ((#s1915 <= 0.5)
                                and ((filesize <= 11259016.0)
                                ) or (#s1915 > 0.5)
                                and ((filesize <= 16839752.0)
                                  or (filesize > 16839752.0)
                                  and ((#s1921 <= 0.5)
                                  ))))) or (#s1906 > 1.0)
                        )))) or (#s717 > 1.5)
                  and ((#s1906 > 1.0)
                  )) or (#s294 > 10.5)
                and ((#s1621 <= 2.0)
                  and ((#s1931 <= 2.0)
                    and ((#s1193 > 0.5)
                      and ((#s290 > 51.0)
                        and ((filesize <= 17175080.0)
                        ))) or (#s1931 > 2.0)
                    and ((#s1698 <= 1.0)
                      and ((#s28 <= 1.0)
                        and ((#s625 > 2.5)
                        ) or (#s28 > 1.0)
                        and ((#s1921 <= 0.5)
                        )) or (#s1698 > 1.0)
                      and ((filesize > 25131176.0)
                        and ((filesize <= 25131192.0)
                        )))))) or (#s1891 > 0.5)
              and ((#s402 <= 1.0)
                and ((#s1299 <= 1.0)
                  and ((#s1955 > 0.5)
                  ))))))) or (#s0 > 0.5)
    )
}